//! End-to-end integration tests over an in-process loopback QUIC connection.
//!
//! This is the Phase 1 acceptance test in miniature: two endpoints on 127.0.0.1
//! exchange a real file with pairing, parallel streams, per-chunk verification,
//! whole-file verification, and (in the fault-injection test) a detected corruption
//! that is transparently re-sent. No hardware, no network beyond loopback.

use std::path::PathBuf;
use std::sync::Arc;

use conduit_core::{
    receive_one, send_file, ConduitEndpoint, DeviceIdentity, ReceiveOptions, SendOptions,
    TransferEvent, TrustStatus, TrustStore,
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
            store.status(session.peer.device_id, &session.peer.fingerprint),
            TrustStatus::Unknown,
            "first contact must be unknown"
        );
        code_tx.send(session.pairing_code().unwrap()).await.unwrap();
        store
            .pin(session.peer.device_id, &session.peer.name, &session.peer.fingerprint)
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

    send_file(session, source, opts, send_events_tx)
        .await
        .expect("send must succeed");
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
