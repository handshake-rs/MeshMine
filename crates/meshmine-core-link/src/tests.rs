use std::os::unix::net::UnixStream;
use std::thread;

use ed25519_dalek::SigningKey;

use crate::{
    CORE_LINK_PROTOCOL_V1, CoreLinkLimits, CoreLinkMessage, HeartbeatV1, authenticate_client,
    authenticate_server,
};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

#[test]
fn mutual_authentication_binds_identity_and_monotonic_frames() {
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let core = key(1);
    let gateway = key(2);
    let core_pubkey = core.verifying_key().to_bytes();
    let gateway_pubkey = gateway.verifying_key().to_bytes();
    // SAFETY: geteuid has no arguments and only reads process credentials.
    let uid = unsafe { libc::geteuid() };
    let server = thread::spawn(move || {
        let mut connection = authenticate_server(
            server_stream,
            2,
            &core,
            gateway_pubkey,
            uid,
            CoreLinkLimits::default(),
        )
        .unwrap();
        let message = connection.receive().unwrap();
        assert!(matches!(message, CoreLinkMessage::Heartbeat(_)));
        connection
            .send(&CoreLinkMessage::Heartbeat(HeartbeatV1 {
                link_protocol_version: CORE_LINK_PROTOCOL_V1,
                network_id: 2,
                sent_at_ms: 11,
                current_bundle_id: [3; 32],
                pending_capture_count: 7,
            }))
            .unwrap();
        connection.connection_id()
    });
    let mut client = authenticate_client(
        client_stream,
        2,
        &gateway,
        core_pubkey,
        CoreLinkLimits::default(),
    )
    .unwrap();
    client
        .send(&CoreLinkMessage::Heartbeat(HeartbeatV1 {
            link_protocol_version: CORE_LINK_PROTOCOL_V1,
            network_id: 2,
            sent_at_ms: 10,
            current_bundle_id: [0; 32],
            pending_capture_count: 0,
        }))
        .unwrap();
    assert!(matches!(
        client.receive().unwrap(),
        CoreLinkMessage::Heartbeat(_)
    ));
    assert_eq!(client.connection_id(), server.join().unwrap());
}

#[test]
fn client_rejects_an_unpinned_core_identity() {
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let core = key(4);
    let gateway = key(5);
    let gateway_pubkey = gateway.verifying_key().to_bytes();
    // SAFETY: geteuid has no arguments and only reads process credentials.
    let uid = unsafe { libc::geteuid() };
    let server = thread::spawn(move || {
        authenticate_server(
            server_stream,
            2,
            &core,
            gateway_pubkey,
            uid,
            CoreLinkLimits::default(),
        )
    });
    let result = authenticate_client(
        client_stream,
        2,
        &gateway,
        key(6).verifying_key().to_bytes(),
        CoreLinkLimits::default(),
    );
    assert!(result.is_err());
    assert!(server.join().unwrap().is_err());
}
