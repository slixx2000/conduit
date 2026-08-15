//! End-to-end integration tests over an in-process loopback QUIC connection.
//!
//! This is the Phase 1 acceptance test in miniature: two endpoints on 127.0.0.1
//! exchange a real file with pairing, parallel streams, per-chunk verification,
//! whole-file verification, and (in the fault-injection test) a detected corruption
//! that is transparently re-sent. No hardware, no network beyond loopback.

use std::path::PathBuf;
use std::sync::Arc;

use conduit_core::{
    receive_one, send_path, serve_session, ConduitEndpoint, DeviceIdentity, FsClient,
    FsEntryKind, ReceiveOptions, SendOptions, Served, TransferEvent, TrustStatus, TrustStore,
};
use rand::RngCore;
use tokio::sync::mpsc;

struct Peer {
    endpoint: ConduitEndpoint,
    identity: Arc<DeviceIdentity>,
    _dir: tempfile::TempDir,
}

fn make_peer(name: &str) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let identity = Arc::new(DeviceIdentity::load_or_create(dir.path(), name).unwrap());
    let endpoint = ConduitEndpoint::bind(
        Arc::clone(&identity),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    Peer {
        endpoint,
        identity,
        _dir: dir,
    }
}

fn random_file(dir: &std::path::Path, len: usize) -> PathBuf {
    let mut data = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut data);
    let path = dir.join("source.bin");
    std::fs::write(&path, &data).unwrap();
    path
}

fn blake3_of(path: &std::path::Path) -> blake3::Hash {
    blake3::hash(&std::fs::read(path).unwrap())
}

async fn drain(mut rx: mpsc::Receiver<TransferEvent>) -> Vec<TransferEvent> {
    let mut out = Vec::new();
    while let Ok(e) = rx.try_recv() {
        out.push(e);
    }
    out
}

/// Run one full transfer between two fresh peers and return
/// (final path, sender events, receiver events).
async fn transfer_roundtrip(
    source: &std::path::Path,
    dest_dir: &std::path::Path,
    opts: SendOptions,
) -> (PathBuf, Vec<TransferEvent>, Vec<TransferEvent>) {
    let alice = make_peer("Alice");
    let bob = make_peer("Bob");
    let bob_addr = bob.endpoint.local_addr().unwrap();

    let (recv_events_tx, recv_events_rx) = mpsc::channel(4096);
    let (send_events_tx, send_events_rx) = mpsc::channel(4096);
    let (code_tx, mut code_rx) = mpsc::channel::<String>(1);

    let dest = dest_dir.to_owned();
    let bob_identity = Arc::clone(&bob.identity);
    let receiver = tokio::spawn(async move {
        let session = bob.endpoint.accept().await.expect("endpoint open").unwrap();

        // Pairing, Bob's side: unknown peer → code shown → user confirms → pin.
        let store_dir = tempfile::tempdir().unwrap();
        let mut store = TrustStore::load(store_dir.path()).unwrap();
        assert_eq!(
            store.status(&session.peer.fingerprint),
            TrustStatus::Unknown,
            "first contact must be unknown"
        );
        code_tx.send(session.pairing_code().unwrap()).await.unwrap();
        store
            .pin(&session.peer.fingerprint, session.peer.device_id, &session.peer.name)
            .unwrap();
        assert_eq!(session.peer.name, "Alice");
        let _ = bob_identity; // keep Bob's identity alive for the session's lifetime

        receive_one(session, ReceiveOptions { dest_dir: dest }, recv_events_tx).await
    });

    let session = alice.endpoint.connect(bob_addr).await.unwrap();
    assert_eq!(session.peer.name, "Bob");

    // Pairing, Alice's side: the code derived from the TLS exporter must match the
    // one Bob computed — that is the whole point of channel binding.
    let alice_code = session.pairing_code().unwrap();
    let bob_code = code_rx.recv().await.unwrap();
    assert_eq!(alice_code, bob_code, "both ends must display the same code");
    assert_eq!(alice_code.len(), 6);

    // A sender failure is usually the *symptom*: the receiver errored and dropped the
    // connection, and "connection lost" is all that reaches this side. Report the
    // receiver's error too rather than leaving the real cause in a joined task.
    if let Err(send_err) = send_path(session, source, opts, send_events_tx).await {
        let recv_err = match receiver.await {
            Ok(Err(e)) => format!("receiver failed with: {e}"),
            Ok(Ok(path)) => format!("receiver succeeded at {}", path.display()),
            Err(join) => format!("receiver task panicked: {join}"),
        };
        panic!("send must succeed: {send_err} ({recv_err})");
    }
    let received = receiver
        .await
        .unwrap()
        .expect("receive must succeed");

    (
        received,
        drain(send_events_rx).await,
        drain(recv_events_rx).await,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_mb_file_arrives_byte_identical_with_live_progress() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    // 24 MiB across 1 MiB chunks: enough chunks to exercise all 4 parallel streams.
    let source = random_file(src_dir.path(), 24 * 1024 * 1024);

    let opts = SendOptions {
        chunk_size: 1024 * 1024,
        ..SendOptions::default()
    };
    let (received, send_events, recv_events) =
        transfer_roundtrip(&source, dest_dir.path(), opts).await;

    assert_eq!(received.file_name().unwrap(), "source.bin");
    assert_eq!(
        blake3_of(&source),
        blake3_of(&received),
        "received file must be byte-identical"
    );

    // Receiver saw the offer, made monotonically increasing progress to 100%, and
    // completed with the final path.
    assert!(matches!(recv_events.first(), Some(TransferEvent::Offered { .. })));
    let progress: Vec<u64> = recv_events
        .iter()
        .filter_map(|e| match e {
            TransferEvent::Progress { bytes_done, .. } => Some(*bytes_done),
            _ => None,
        })
        .collect();
    assert!(!progress.is_empty(), "expected live progress events");
    assert!(
        progress.windows(2).all(|w| w[0] <= w[1]),
        "progress must be monotonic: {progress:?}"
    );
    assert_eq!(*progress.last().unwrap(), 24 * 1024 * 1024);
    assert!(recv_events
        .iter()
        .any(|e| matches!(e, TransferEvent::Completed { path: Some(_), .. })));

    // Sender got receiver-fed progress and a completion.
    assert!(send_events
        .iter()
        .any(|e| matches!(e, TransferEvent::Completed { .. })));
    assert!(
        !send_events
            .iter()
            .any(|e| matches!(e, TransferEvent::ChunkResent { .. })),
        "clean run must not resend"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_chunk_is_detected_and_resent() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let source = random_file(src_dir.path(), 8 * 1024 * 1024);

    let opts = SendOptions {
        chunk_size: 1024 * 1024,
        corrupt_chunk_once: Some((0, 3)),
        ..SendOptions::default()
    };
    let (received, send_events, recv_events) =
        transfer_roundtrip(&source, dest_dir.path(), opts).await;

    // The corruption was caught by the per-chunk BLAKE3 check and repaired.
    assert!(
        recv_events.iter().any(|e| matches!(
            e,
            TransferEvent::ChunkResent { entry_index: 0, chunk_index: 3, .. }
        )),
        "receiver must flag the corrupted chunk: {recv_events:?}"
    );
    assert!(
        send_events
            .iter()
            .any(|e| matches!(e, TransferEvent::ChunkResent { .. })),
        "sender must service the resend request"
    );
    assert_eq!(
        blake3_of(&source),
        blake3_of(&received),
        "file must still arrive byte-identical after the resend"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tiny_and_empty_files_transfer_correctly() {
    for len in [0usize, 1, 4096] {
        let src_dir = tempfile::tempdir().unwrap();
        let dest_dir = tempfile::tempdir().unwrap();
        let source = random_file(src_dir.path(), len);

        let (received, _send_events, _recv_events) =
            transfer_roundtrip(&source, dest_dir.path(), SendOptions::default()).await;
        assert_eq!(
            blake3_of(&source),
            blake3_of(&received),
            "{len}-byte file must arrive intact"
        );
        assert_eq!(std::fs::metadata(&received).unwrap().len() as usize, len);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn folder_tree_transfers_recursively() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();

    let root = src_dir.path().join("photos");
    std::fs::create_dir_all(root.join("2024/trip")).unwrap();
    std::fs::create_dir_all(root.join("empty-album")).unwrap();
    let mut big = vec![0u8; 3 * 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut big);
    std::fs::write(root.join("2024/trip/big.raw"), &big).unwrap();
    std::fs::write(root.join("2024/note.txt"), b"hello from 2024").unwrap();
    std::fs::write(root.join("cover.jpg"), b"tiny").unwrap();
    std::fs::write(root.join("zero.dat"), b"").unwrap();

    let opts = SendOptions {
        chunk_size: 1024 * 1024,
        ..SendOptions::default()
    };
    let (received, _send_events, recv_events) =
        transfer_roundtrip(&root, dest_dir.path(), opts).await;

    assert_eq!(received, dest_dir.path().join("photos"));
    for rel in ["2024/trip/big.raw", "2024/note.txt", "cover.jpg", "zero.dat"] {
        assert_eq!(
            blake3_of(&root.join(rel)),
            blake3_of(&received.join(rel)),
            "{rel} must arrive byte-identical"
        );
    }
    assert!(received.join("empty-album").is_dir(), "empty dirs must exist");
    assert!(
        !dest_dir.path().join(".conduit").exists()
            && std::fs::read_dir(dest_dir.path()).unwrap().count() == 1,
        "staging dir must be cleaned up"
    );
    assert!(recv_events
        .iter()
        .any(|e| matches!(e, TransferEvent::Completed { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_transfer_resumes_without_resending_completed_chunks() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    // Random content so a staged chunk can only pass the resume rescan if it was
    // genuinely received. Big enough that the abort lands mid-transfer.
    let source = random_file(src_dir.path(), 96 * 1024 * 1024);
    let opts = SendOptions {
        chunk_size: 1024 * 1024,
        ..SendOptions::default()
    };

    // --- Run 1: kill the receiver once some bytes are verified on disk. ---
    let alice = make_peer("Alice");
    let bob = make_peer("Bob");
    let bob_addr = bob.endpoint.local_addr().unwrap();
    let dest = dest_dir.path().to_owned();

    let (recv_events_tx, mut recv_events_rx) = mpsc::channel(4096);
    let receiver = tokio::spawn(async move {
        let session = bob.endpoint.accept().await.unwrap().unwrap();
        receive_one(session, ReceiveOptions { dest_dir: dest }, recv_events_tx).await
    });

    let session = alice.endpoint.connect(bob_addr).await.unwrap();
    let (send_events_tx, _send_events_rx) = mpsc::channel(4096);
    let sender = tokio::spawn({
        let source = source.clone();
        let opts = opts.clone();
        async move { send_path(session, &source, opts, send_events_tx).await }
    });

    // Wait until the receiver has verified at least 8 MiB, then pull the plug.
    let interrupted_at = loop {
        match recv_events_rx.recv().await {
            Some(TransferEvent::Progress { bytes_done, .. }) if bytes_done >= 8 * 1024 * 1024 => {
                receiver.abort();
                break bytes_done;
            }
            Some(TransferEvent::Completed { .. }) => {
                panic!("transfer finished before the abort — enlarge the test file");
            }
            Some(_) => continue,
            None => panic!("receiver events ended before any progress"),
        }
    };
    assert!(
        sender.await.unwrap().is_err(),
        "sender must fail when the receiver vanishes"
    );

    let staging: Vec<_> = std::fs::read_dir(dest_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".conduit-"))
        .collect();
    assert_eq!(staging.len(), 1, "the partial must stay staged for resume");

    // --- Run 2: same source, fresh connection — must resume, not restart. ---
    let (received, send_events, recv_events) =
        transfer_roundtrip(&source, dest_dir.path(), opts).await;

    let resumed = send_events
        .iter()
        .find_map(|e| match e {
            TransferEvent::Resumed { bytes_already, .. } => Some(*bytes_already),
            _ => None,
        })
        .expect("sender must observe a resume via the Accept bitmap");
    assert!(
        resumed >= interrupted_at,
        "resume must cover at least the {interrupted_at} bytes verified before the cut, got {resumed}"
    );
    assert!(recv_events
        .iter()
        .any(|e| matches!(e, TransferEvent::Resumed { .. })));

    assert_eq!(
        blake3_of(&source),
        blake3_of(&received),
        "resumed file must arrive byte-identical"
    );
    let leftovers: Vec<_> = std::fs::read_dir(dest_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".conduit-"))
        .collect();
    assert!(leftovers.is_empty(), "staging must be cleaned up after success");
}

#[tokio::test(flavor = "multi_thread")]
async fn fs_session_serves_listings_reads_and_mutations() {
    let share = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(share.path().join("docs")).unwrap();
    let mut blob = vec![0u8; 3_000_000];
    rand::thread_rng().fill_bytes(&mut blob);
    std::fs::write(share.path().join("blob.bin"), &blob).unwrap();
    std::fs::write(share.path().join("docs/readme.txt"), b"hello mount").unwrap();
    // Plumbing that must stay invisible to the peer.
    std::fs::create_dir_all(share.path().join(".conduit-abc.part")).unwrap();

    let alice = make_peer("Alice");
    let bob = make_peer("Bob");
    let bob_addr = bob.endpoint.local_addr().unwrap();
    let share_root = share.path().to_owned();

    let server = tokio::spawn(async move {
        let session = bob.endpoint.accept().await.unwrap().unwrap();
        let (tx, _rx) = mpsc::channel(16);
        serve_session(
            session,
            ReceiveOptions {
                dest_dir: std::env::temp_dir(),
            },
            share_root,
            tx,
        )
        .await
    });

    let session = alice.endpoint.connect(bob_addr).await.unwrap();
    let fs = FsClient::start(session).unwrap();

    // Listing: sorted, staging dir hidden.
    let root = fs.list_dir("").await.unwrap();
    let names: Vec<(&str, FsEntryKind)> =
        root.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(
        names,
        vec![("blob.bin", FsEntryKind::File), ("docs", FsEntryKind::Dir)]
    );
    assert_eq!(root[0].size, blob.len() as u64);

    // Stat.
    let attr = fs.stat("docs/readme.txt").await.unwrap();
    assert_eq!(attr.kind, FsEntryKind::File);
    assert_eq!(attr.size, 11);
    assert!(attr.modified_unix > 0);

    // Ranged reads: middle window, then a short read past EOF.
    let window = fs.read_range("blob.bin", 1_000_000, 65_536).await.unwrap();
    assert_eq!(window, &blob[1_000_000..1_065_536]);
    let tail = fs.read_range("blob.bin", blob.len() as u64 - 10, 4096).await.unwrap();
    assert_eq!(tail, &blob[blob.len() - 10..]);
    let full = fs.read_range("docs/readme.txt", 0, 4096).await.unwrap();
    assert_eq!(full, b"hello mount");

    // Concurrent reads keep their request/payload correlation straight.
    let (a, b, c) = tokio::join!(
        fs.read_range("blob.bin", 0, 100_000),
        fs.read_range("blob.bin", 2_000_000, 100_000),
        fs.read_range("docs/readme.txt", 6, 100),
    );
    assert_eq!(a.unwrap(), &blob[..100_000]);
    assert_eq!(b.unwrap(), &blob[2_000_000..2_100_000]);
    assert_eq!(c.unwrap(), b"mount");

    // Mutations act on the real share.
    fs.mkdir("docs/new").await.unwrap();
    assert!(share.path().join("docs/new").is_dir());
    fs.rename("docs/readme.txt", "docs/new/readme.txt").await.unwrap();
    assert!(share.path().join("docs/new/readme.txt").is_file());
    fs.unlink("docs/new/readme.txt").await.unwrap();
    assert!(!share.path().join("docs/new/readme.txt").exists());

    // Failures are per-op, not per-session.
    assert!(fs.stat("no-such-file").await.is_err());
    assert!(fs.read_range("../escape", 0, 16).await.is_err());
    assert!(fs.unlink("docs").await.is_err(), "unlink refuses directories");
    let survives = fs.list_dir("docs").await.unwrap();
    assert_eq!(survives.len(), 1, "session must survive failed ops");

    // Unmount: the serving side ends cleanly.
    fs.close();
    let served = tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("server must end after unmount")
        .unwrap()
        .expect("fs session must end cleanly");
    assert!(matches!(served, Served::FsSession));
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_session_still_dispatches_transfers() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let source = random_file(src_dir.path(), 512 * 1024);

    let alice = make_peer("Alice");
    let bob = make_peer("Bob");
    let bob_addr = bob.endpoint.local_addr().unwrap();
    let dest = dest_dir.path().to_owned();

    let server = tokio::spawn(async move {
        let session = bob.endpoint.accept().await.unwrap().unwrap();
        let (tx, _rx) = mpsc::channel(1024);
        serve_session(
            session,
            ReceiveOptions { dest_dir: dest },
            std::env::temp_dir(),
            tx,
        )
        .await
    });

    let session = alice.endpoint.connect(bob_addr).await.unwrap();
    let (tx, _rx) = mpsc::channel(1024);
    send_path(session, &source, SendOptions::default(), tx)
        .await
        .unwrap();

    match server.await.unwrap().unwrap() {
        Served::Transfer(path) => assert_eq!(blake3_of(&source), blake3_of(&path)),
        other => panic!("expected a transfer, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn receiving_into_a_dir_with_a_same_named_file_does_not_clobber() {
    let src_dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let source = random_file(src_dir.path(), 128 * 1024);

    // A pre-existing, different file with the destination name.
    std::fs::write(dest_dir.path().join("source.bin"), b"do not overwrite me").unwrap();

    let (received, _s, _r) =
        transfer_roundtrip(&source, dest_dir.path(), SendOptions::default()).await;

    assert_eq!(received, dest_dir.path().join("source (1).bin"));
    assert_eq!(blake3_of(&source), blake3_of(&received));
    assert_eq!(
        std::fs::read(dest_dir.path().join("source.bin")).unwrap(),
        b"do not overwrite me"
    );
}
