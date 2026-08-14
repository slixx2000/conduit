//! Headless driver for Conduit.
//!
//! Exists so the transfer pipeline can be exercised and benchmarked without the GUI —
//! two `conduit` processes on one machine are the Phase 1 end-to-end test, and the
//! throughput numbers in Phase 2 come from here.
//!
//! `send`/`receive` drive the real Phase 1 pipeline: QUIC + TLS 1.3, TOFU pairing
//! with a 6-digit code, chunked parallel streams, per-chunk and whole-file BLAKE3.
//! `hash` verifies a transferred file byte-for-byte against its source.

use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use conduit_core::{
    receive_one, send_file, ByeReason, ConduitEndpoint, DeviceIdentity, PeerSession,
    ReceiveOptions, SendOptions, TransferEvent, TrustStatus, TrustStore,
};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "conduit", version, about = "Headless Conduit driver", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print version and protocol information.
    Version,
    /// Report link selection and platform readiness.
    Doctor,
    /// Print the BLAKE3 hash of a file, for verifying a transfer arrived intact.
    Hash {
        /// File to hash. Use `-` to read stdin.
        path: PathBuf,
    },
    /// Wait for one inbound transfer and write it to disk.
    Receive {
        /// Address to listen on. Port 0 picks a free port (printed on startup).
        #[arg(long, default_value = "0.0.0.0:0")]
        listen: SocketAddr,
        /// Directory the received file lands in.
        #[arg(long, default_value = ".")]
        dest: PathBuf,
        /// Keep accepting transfers instead of exiting after the first. This is the
        /// far end of `conduit bench`.
        #[arg(long)]
        forever: bool,
        #[command(flatten)]
        common: CommonOpts,
    },
    /// Send one file to a listening peer.
    Send {
        /// File to send.
        file: PathBuf,
        /// Peer address, e.g. 192.168.1.20:4433 (printed by `conduit receive`).
        #[arg(long)]
        to: SocketAddr,
        /// Parallel QUIC data streams.
        #[arg(long, default_value_t = conduit_core::DEFAULT_STREAM_COUNT)]
        streams: usize,
        /// Chunk size in MiB.
        #[arg(long, default_value_t = 4)]
        chunk_mib: u32,
        #[command(flatten)]
        common: CommonOpts,
    },
    /// Measure end-to-end throughput against a listening peer (run
    /// `conduit receive --forever --trust` on the far end). Sends a sparse
    /// zero-filled file through the full pipeline — manifest hashing, TLS, chunk
    /// verification, disk writes — once per streams x chunk-size combination.
    Bench {
        /// Peer address (printed by `conduit receive`).
        #[arg(long)]
        to: SocketAddr,
        /// Payload size per run, in GiB.
        #[arg(long, default_value_t = 1.0)]
        size_gib: f64,
        /// Stream counts to try. Repeat the flag to sweep, e.g. --streams 1 --streams 4.
        #[arg(long, default_values_t = [conduit_core::DEFAULT_STREAM_COUNT])]
        streams: Vec<usize>,
        /// Chunk sizes (MiB) to try. Repeat the flag to sweep.
        #[arg(long, default_values_t = [4u32])]
        chunk_mib: Vec<u32>,
        #[command(flatten)]
        common: CommonOpts,
    },
}

#[derive(clap::Args)]
struct CommonOpts {
    /// Directory holding this device's identity and trust store.
    /// Defaults to the OS config dir; override to run two instances on one machine.
    #[arg(long)]
    identity_dir: Option<PathBuf>,
    /// Trust new peers without the interactive pairing prompt. For scripted tests
    /// on trusted networks only — the code display is the MITM defence.
    #[arg(long)]
    trust: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Version => {
            println!("conduit {}", env!("CARGO_PKG_VERSION"));
            println!("protocol v{}", conduit_core::PROTOCOL_VERSION);
            println!("service  {}", conduit_discovery::SERVICE_TYPE);
            ExitCode::SUCCESS
        }

        Command::Doctor => doctor(),

        Command::Hash { path } => match hash_file(&path) {
            Ok(hash) => {
                println!("{hash}  {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: cannot hash {}: {e}", path.display());
                ExitCode::FAILURE
            }
        },

        Command::Receive {
            listen,
            dest,
            forever,
            common,
        } => run(receive(listen, dest, forever, common)).await,

        Command::Send {
            file,
            to,
            streams,
            chunk_mib,
            common,
        } => run(send(file, to, streams, chunk_mib, common)).await,

        Command::Bench {
            to,
            size_gib,
            streams,
            chunk_mib,
            common,
        } => run(bench(to, size_gib, streams, chunk_mib, common)).await,
    }
}

async fn run(fut: impl std::future::Future<Output = conduit_core::Result<()>>) -> ExitCode {
    match fut.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn receive(
    listen: SocketAddr,
    dest: PathBuf,
    forever: bool,
    common: CommonOpts,
) -> conduit_core::Result<()> {
    let (endpoint, mut store) = open_endpoint(&common, listen)?;
    println!(
        "listening on {} — run `conduit send <file> --to <this address>` on the peer",
        endpoint.local_addr()?
    );

    loop {
        let session = match endpoint.accept().await {
            Some(session) => session?,
            None => return Err(conduit_core::Error::Connection("endpoint closed".into())),
        };
        println!(
            "connection from {} ({})",
            session.peer.name,
            session.remote_address()
        );

        let session = pair(session, &mut store, common.trust).await?;

        let (events_tx, events_rx) = mpsc::channel(256);
        let printer = tokio::spawn(print_events(events_rx));
        let result = receive_one(session, ReceiveOptions { dest_dir: dest.clone() }, events_tx).await;
        let _ = printer.await;

        match result {
            Ok(path) => println!("received: {}", path.display()),
            // In forever mode a failed transfer (peer vanished, hash mismatch) must
            // not take the listener down with it.
            Err(e) if forever => eprintln!("transfer failed: {e}"),
            Err(e) => return Err(e),
        }
        if !forever {
            return Ok(());
        }
    }
}

async fn send(
    file: PathBuf,
    to: SocketAddr,
    streams: usize,
    chunk_mib: u32,
    common: CommonOpts,
) -> conduit_core::Result<()> {
    let (endpoint, mut store) = open_endpoint(&common, "0.0.0.0:0".parse().unwrap())?;

    println!("connecting to {to} …");
    let session = endpoint.connect(to).await?;
    println!("connected to {}", session.peer.name);

    let session = pair(session, &mut store, common.trust).await?;

    let opts = SendOptions {
        chunk_size: chunk_mib.max(1) * 1024 * 1024,
        streams,
        corrupt_chunk_once: None,
    };
    let (events_tx, events_rx) = mpsc::channel(256);
    let printer = tokio::spawn(print_events(events_rx));
    let result = send_file(session, &file, opts, events_tx).await;
    let _ = printer.await;

    result?;
    println!("sent: {}", file.display());
    Ok(())
}

/// Throughput matrix: one full transfer per (streams, chunk) combination. The peer
/// runs `conduit receive --forever --trust`, so every run exercises the complete
/// pipeline including the receiver's verification and disk writes.
async fn bench(
    to: SocketAddr,
    size_gib: f64,
    streams: Vec<usize>,
    chunk_mib: Vec<u32>,
    common: CommonOpts,
) -> conduit_core::Result<()> {
    let size_bytes = (size_gib * (1u64 << 30) as f64) as u64;

    // Sparse zero file: reads cost no disk I/O, so the link and protocol are what's
    // being measured — while hashing, TLS, and receiver-side writes stay real.
    let dir = tempfile_dir()?;
    let payload = dir.join(format!("bench-{size_gib}gib.bin"));
    {
        let f = std::fs::File::create(&payload)?;
        f.set_len(size_bytes)?;
    }

    let (endpoint, mut store) = open_endpoint(&common, "0.0.0.0:0".parse().unwrap())?;
    println!("benchmarking against {to} with {size_gib} GiB per run\n");
    println!("{:<9}{:<11}{:<11}throughput", "streams", "chunk", "time");

    let mut best: Option<(usize, u32, f64)> = None;
    for &n_streams in &streams {
        for &mib in &chunk_mib {
            let session = endpoint.connect(to).await?;
            let session = pair(session, &mut store, common.trust).await?;

            let opts = SendOptions {
                chunk_size: mib.max(1) * 1024 * 1024,
                streams: n_streams,
                corrupt_chunk_once: None,
            };
            // Progress must be consumed (or the engine's sends would be dropped
            // silently anyway) but stays off the terminal during a matrix run.
            let (events_tx, mut events_rx) = mpsc::channel(256);
            let drain = tokio::spawn(async move { while events_rx.recv().await.is_some() {} });

            let started = std::time::Instant::now();
            let result = send_file(session, &payload, opts, events_tx).await;
            let elapsed = started.elapsed().as_secs_f64();
            let _ = drain.await;
            result?;

            let gbps = size_bytes as f64 * 8.0 / elapsed / 1e9;
            println!(
                "{:<9}{:<11}{:<11}{:.2} Gbit/s",
                n_streams,
                format!("{mib} MiB"),
                format!("{elapsed:.2} s"),
                gbps
            );
            if best.is_none_or(|(_, _, b)| gbps > b) {
                best = Some((n_streams, mib, gbps));
            }
        }
    }

    if let Some((s, c, g)) = best {
        println!("\nbest: {s} stream(s) x {c} MiB chunks -> {g:.2} Gbit/s");
    }
    let _ = std::fs::remove_file(&payload);
    Ok(())
}

fn tempfile_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("conduit-bench");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn open_endpoint(
    common: &CommonOpts,
    listen: SocketAddr,
) -> conduit_core::Result<(ConduitEndpoint, TrustStore)> {
    let dir = common
        .identity_dir
        .clone()
        .or_else(|| dirs::config_dir().map(|d| d.join("conduit")))
        .ok_or_else(|| {
            conduit_core::Error::Crypto(
                "no OS config directory found — pass --identity-dir".into(),
            )
        })?;
    let identity = Arc::new(DeviceIdentity::load_or_create(&dir, &host_name())?);
    let store = TrustStore::load(&dir)?;
    let endpoint = ConduitEndpoint::bind(identity, listen)?;
    Ok((endpoint, store))
}

/// TOFU: silently continue for pinned peers, run the 6-digit code confirmation for
/// unknown ones, and refuse loudly when a pinned fingerprint no longer matches.
async fn pair(
    session: PeerSession,
    store: &mut TrustStore,
    auto_trust: bool,
) -> conduit_core::Result<PeerSession> {
    match store.status(session.peer.device_id, &session.peer.fingerprint) {
        TrustStatus::Trusted => Ok(session),
        TrustStatus::Mismatch { pinned } => {
            let presented = session.peer.fingerprint.hex();
            session.bye(ByeReason::Other("fingerprint mismatch".into())).await;
            Err(conduit_core::Error::FingerprintMismatch { pinned, presented })
        }
        TrustStatus::Unknown => {
            let code = session.pairing_code()?;
            println!("\npairing code: {} {}", &code[..3], &code[3..]);
            let confirmed = auto_trust || {
                println!("confirm that the SAME code is shown on the other device.");
                prompt_yes_no("codes match? [y/N] ").await?
            };
            if confirmed {
                store.pin(
                    session.peer.device_id,
                    &session.peer.name,
                    &session.peer.fingerprint,
                )?;
                println!(
                    "paired with {} ({})",
                    session.peer.name,
                    session.peer.fingerprint.short()
                );
                Ok(session)
            } else {
                session.bye(ByeReason::PairingRejected).await;
                Err(conduit_core::Error::PairingRejected)
            }
        }
    }
}

async fn prompt_yes_no(prompt: &str) -> conduit_core::Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let line = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await
    .map_err(|e| conduit_core::Error::Protocol(format!("stdin task panicked: {e}")))??;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Render transfer events as a single self-overwriting progress line.
async fn print_events(mut events: mpsc::Receiver<TransferEvent>) {
    use std::io::Write;
    while let Some(event) = events.recv().await {
        match event {
            TransferEvent::Offered { name, total_bytes, .. } => {
                println!("incoming: {name} ({})", human_bytes(total_bytes));
            }
            TransferEvent::Started { name, total_bytes, .. } => {
                println!("transferring {name} ({})", human_bytes(total_bytes));
            }
            TransferEvent::Progress { bytes_done, total_bytes, .. } => {
                let pct = if total_bytes == 0 {
                    100.0
                } else {
                    bytes_done as f64 / total_bytes as f64 * 100.0
                };
                print!(
                    "\r  {pct:5.1}%  {} / {}    ",
                    human_bytes(bytes_done),
                    human_bytes(total_bytes)
                );
                let _ = std::io::stdout().flush();
            }
            TransferEvent::ChunkResent { entry_index, chunk_index, .. } => {
                println!("\n  chunk {chunk_index} of entry {entry_index} failed its hash — resending");
            }
            TransferEvent::Verifying { .. } => {
                println!("\n  verifying whole-file BLAKE3 …");
            }
            TransferEvent::Completed { .. } => println!("  done."),
            TransferEvent::Failed { reason, .. } => println!("\n  FAILED: {reason}"),
        }
    }
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = b as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{b} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "conduit-device".into())
}

fn doctor() -> ExitCode {
    println!("protocol       v{}", conduit_core::PROTOCOL_VERSION);
    println!("default chunk  {} bytes", conduit_core::DEFAULT_CHUNK_SIZE);
    println!("mount driver   {}", conduit_fs::REQUIRED_DRIVER);

    match conduit_net::detect_links() {
        Ok(links) if links.is_empty() => {
            println!("link           none detected — falling back to OS routing (LAN/loopback)");
        }
        Ok(links) => {
            for link in &links {
                println!(
                    "link           {} {:?} {}",
                    link.interface, link.kind, link.addr
                );
            }
            match conduit_net::select_preferred(&links) {
                Some(chosen) => println!("preferred      {} ({:?})", chosen.interface, chosen.kind),
                None => println!("preferred      none usable — check Thunderbolt authorization"),
            }
        }
        Err(e) => {
            eprintln!("error: link detection failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

/// Stream the file through the hasher rather than reading it into memory — these are
/// multi-gigabyte files by design.
fn hash_file(path: &PathBuf) -> std::io::Result<String> {
    let mut hasher = conduit_core::FileHasher::new();
    let mut buf = vec![0u8; conduit_core::DEFAULT_CHUNK_SIZE as usize];

    let mut source: Box<dyn Read> = if path.as_os_str() == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };

    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize_hex())
}
