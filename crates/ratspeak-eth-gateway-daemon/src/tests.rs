use std::collections::VecDeque;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;
use ratspeak_eth_gateway::{
    AcceptedEvidenceRequest, AcceptedSignedRelay, GatewayBundle, GatewayExecutionProvider,
    GatewayProviderFailure, RelayProviderObservation, RelayProviderStatus,
};
use ratspeak_eth_node::{
    EthereumNodeStore, MessageRequestStatus, MessagingEvidenceKind, NodeMessageOutcome,
    OutboundEvidenceRequest, OutboundMessageBinding,
};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_link::link::Link;
use rns_transport::link_messages::{DestinationEvent, PacketMetrics};
use rns_transport::messages::{LinkEndpointBindResult, LinkEndpointSendResult, TransportMessage};

use super::*;

const REQUESTER: [u8; 16] = [0x31; 16];
const RAW_NATIVE_TRANSFER: &str = "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725";

#[test]
fn requester_contact_card_derives_exact_public_authentication_material() {
    assert_eq!(
        sanitize_contact_card_name(&format!("  {} ignored", "é".repeat(64))),
        "é".repeat(62)
    );
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = Identity::new();
    let public_key = identity.get_public_key();
    let source =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let card = format!(
        "RSCP1::{}:{}:{}",
        hex::encode(source),
        hex::encode(identity.hash),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
    );
    let path = temp.path().join("requester.rscp1");
    std::fs::write(&path, &card).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let requester = RequesterConfig {
        source_hash: String::new(),
        ed25519_public_key: String::new(),
        rns_public_key: None,
        contact_card_path: Some(path),
    };
    let material = parse_rscp1_contact_card(card.as_bytes()).unwrap();
    assert_eq!(material.source_hash, source);
    assert_eq!(material.ed25519_public_key, public_key[32..]);
    assert_eq!(material.rns_public_key.unwrap(), public_key);
    let prefixed = card.replacen(
        &hex::encode(source),
        &format!("0x{}", hex::encode(source)),
        1,
    );
    assert!(parse_rscp1_contact_card(prefixed.as_bytes()).is_err());
    let compatible_long_name = format!(
        "RSCP1:{}:{}:{}:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("x".repeat(80)),
        hex::encode_upper(source),
        hex::encode_upper(identity.hash),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
    );
    assert!(parse_rscp1_contact_card(compatible_long_name.as_bytes()).is_ok());

    let mixed = RequesterConfig {
        source_hash: hex::encode(source),
        ..requester.clone()
    };
    assert!(requester_public_material(&mixed).is_err());

    let requester_key = Ed25519PrivateKey::from_bytes(&[0x53; 32]);
    let mut daemon_config = config(temp.path(), &requester_key);
    daemon_config.requesters = vec![requester];
    daemon_config.normalize_contact_cards().unwrap();
    assert!(daemon_config.requesters[0].contact_card_path.is_none());
    std::fs::remove_file(temp.path().join("requester.rscp1")).unwrap();
    assert_eq!(daemon_config.requester_keys().unwrap().len(), 1);
    assert_eq!(daemon_config.requester_rns_keys().unwrap().len(), 1);

    let mut aliased = config(temp.path(), &requester_key);
    aliased.requesters[0] = RequesterConfig {
        source_hash: String::new(),
        ed25519_public_key: String::new(),
        rns_public_key: None,
        contact_card_path: Some(aliased.service_identity_path.clone()),
    };
    assert!(aliased.normalize_contact_cards().is_err());

    let mixed_path = temp.path().join("mixed-config.json");
    let mixed_json = serde_json::json!({
        "rns_config_dir": temp.path().join("rns"),
        "service_identity_path": temp.path().join("service.identity"),
        "durable_gateway_db": temp.path().join("gateway.sqlite"),
        "instance_lock_path": temp.path().join("gateway.lock"),
        "requesters": [{
            "source_hash": hex::encode(source),
            "contact_card_path": temp.path().join("requester.rscp1")
        }],
        "provider": {
            "checkpoint_root": hex::encode([0x44; 32]),
            "checkpoint_epoch": 1,
            "consensus_floor_path": temp.path().join("consensus.floor"),
            "beacon_rpc_endpoint": "https://beacon.invalid",
            "execution_rpc_endpoint": "https://execution.invalid"
        },
        "policy": {}
    });
    std::fs::write(&mixed_path, serde_json::to_vec(&mixed_json).unwrap()).unwrap();
    std::fs::set_permissions(&mixed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        GatewayDaemonConfig::load(&mixed_path),
        Err(DaemonError::InvalidConfiguration)
    ));
}

struct FixtureProvider {
    relay: VecDeque<Result<RelayProviderStatus, GatewayProviderFailure>>,
    status: VecDeque<
        Result<ratspeak_eth_gateway::TransactionStatusObservation, GatewayProviderFailure>,
    >,
}

impl FixtureProvider {
    fn accepted() -> Self {
        Self {
            relay: VecDeque::from([Ok(RelayProviderStatus::Accepted)]),
            status: VecDeque::new(),
        }
    }

    fn transient_then_accepted() -> Self {
        Self {
            relay: VecDeque::from([
                Err(GatewayProviderFailure::Transient),
                Ok(RelayProviderStatus::Accepted),
            ]),
            status: VecDeque::new(),
        }
    }
}

impl GatewayExecutionProvider for FixtureProvider {
    fn submit_signed_relay(
        &mut self,
        relay: &AcceptedSignedRelay,
    ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
        let status = self
            .relay
            .pop_front()
            .unwrap_or(Ok(RelayProviderStatus::Accepted))?;
        Ok(RelayProviderObservation::new(relay.tx_hash(), status))
    }

    fn observe_transaction_status(
        &mut self,
        _request: &ratspeak_eth_gateway::AcceptedTransactionStatusRequest,
    ) -> Result<ratspeak_eth_gateway::TransactionStatusObservation, GatewayProviderFailure> {
        self.status
            .pop_front()
            .unwrap_or(Err(GatewayProviderFailure::Permanent))
    }

    fn fetch_verified_evidence(
        &mut self,
        _request: &AcceptedEvidenceRequest,
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        Err(GatewayProviderFailure::Permanent)
    }
}

#[derive(Default)]
struct RecordingTransport {
    sent: Vec<SealedOutboundLxmf>,
    observation: Option<TransportObservation>,
}

impl OutboundLxmfTransport for RecordingTransport {
    fn send(&mut self, message: SealedOutboundLxmf) -> Result<TransportObservation, DaemonError> {
        self.sent.push(message);
        Ok(self
            .observation
            .unwrap_or(TransportObservation::AcceptedForDelivery))
    }
}

fn private_temp() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

fn config(temp: &Path, requester_key: &Ed25519PrivateKey) -> GatewayDaemonConfig {
    GatewayDaemonConfig {
        rns_config_dir: temp.join("rns"),
        service_identity_path: temp.join("service.identity"),
        durable_gateway_db: temp.join("gateway.sqlite"),
        instance_lock_path: temp.join("gateway.lock"),
        requesters: vec![RequesterConfig {
            source_hash: hex::encode(REQUESTER),
            ed25519_public_key: hex::encode(requester_key.public_key().to_bytes()),
            rns_public_key: None,
            contact_card_path: None,
        }],
        provider: ProviderConfig {
            checkpoint_root: hex::encode([0x44; 32]),
            checkpoint_epoch: 1,
            consensus_floor_path: temp.join("consensus.floor"),
            beacon_rpc_endpoint: "https://beacon.invalid".into(),
            execution_rpc_endpoint: "https://rpc.invalid".into(),
            beacon_authorization_path: None,
            execution_authorization_path: None,
            allow_loopback_http_for_development: false,
        },
        propagation: None,
        policy: DaemonPolicyConfig::default(),
    }
}

fn relay_wire(request_id: [u8; 16], expires: u64) -> Vec<u8> {
    let raw = hex::decode(RAW_NATIVE_TRANSFER).unwrap();
    let mut bytes = b"RSETHM1".to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&ratspeak_eth_verifier::SEPOLIA_CHAIN_ID.to_le_bytes());
    bytes.push(4);
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&expires.to_le_bytes());
    bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&raw);
    bytes
}

fn packed_request(
    key: &Ed25519PrivateKey,
    service_hash: [u8; 16],
    request_id: [u8; 16],
) -> Vec<u8> {
    let mut message = LxMessage::new(service_hash, REQUESTER, "", "", DeliveryMethod::Direct);
    message
        .set_file_attachment_field(
            ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME,
            &relay_wire(request_id, 10_000),
        )
        .unwrap();
    message.sign(key).unwrap();
    message.pack().unwrap()
}

fn packed_status_request(
    key: &Ed25519PrivateKey,
    service_hash: [u8; 16],
    request_id: [u8; 16],
    tx_hash: [u8; 32],
) -> Vec<u8> {
    let mut wire = b"RSETHM1".to_vec();
    wire.push(1);
    wire.extend_from_slice(&ratspeak_eth_verifier::SEPOLIA_CHAIN_ID.to_le_bytes());
    wire.push(8);
    wire.extend_from_slice(&request_id);
    wire.extend_from_slice(&10_000_u64.to_le_bytes());
    wire.extend_from_slice(&tx_hash);
    assert_eq!(wire.len(), 73);
    let mut message = LxMessage::new(service_hash, REQUESTER, "", "", DeliveryMethod::Direct);
    message
        .set_file_attachment_field(ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME, &wire)
        .unwrap();
    message.sign(key).unwrap();
    message.pack().unwrap()
}

fn daemon(
    temp: &Path,
    requester_key: &Ed25519PrivateKey,
    provider: FixtureProvider,
) -> (
    GatewayDaemon<FixtureProvider>,
    Identity,
    GatewayDaemonConfig,
) {
    let identity = Identity::new();
    let config = config(temp, requester_key);
    let daemon = GatewayDaemon::open(&config, &identity, provider).unwrap();
    (daemon, identity, config)
}

#[test]
fn authenticated_routes_and_exact_attachment_are_accepted() {
    for (index, route) in [
        InboundRoute::Opportunistic,
        InboundRoute::Direct,
        InboundRoute::Propagated,
    ]
    .into_iter()
    .enumerate()
    {
        let temp = private_temp();
        let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
        let (mut daemon, identity, _) =
            daemon(temp.path(), &requester_key, FixtureProvider::accepted());
        let service_hash =
            Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
        let mut transport = RecordingTransport::default();
        assert_eq!(
            daemon
                .handle_packed(
                    &packed_request(&requester_key, service_hash, [index as u8 + 1; 16]),
                    route,
                    10,
                    &mut transport,
                )
                .unwrap(),
            1
        );
        let outbound = LxMessage::unpack(transport.sent[0].packed_message()).unwrap();
        assert!(transport.sent[0].propagation_fallback().is_none());
        assert_eq!(outbound.destination_hash, REQUESTER);
        let (name, attachment) = outbound.first_file_attachment().unwrap().unwrap();
        assert_eq!(name, ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME);
        assert!(!attachment.is_empty());
        let private = identity.get_private_key().unwrap();
        let mut seed = [0; 32];
        seed.copy_from_slice(&private[32..]);
        assert!(
            outbound
                .clone()
                .verify(&Ed25519PrivateKey::from_bytes(&seed).public_key())
        );
    }
}

#[test]
fn authenticated_transaction_status_is_signed_durable_and_duplicate_safe() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let tx_hash = [0x71; 32];
    let mut provider = FixtureProvider::accepted();
    provider
        .status
        .push_back(Ok(ratspeak_eth_gateway::TransactionStatusObservation::new(
            tx_hash,
            ratspeak_eth_gateway::TransactionPresence::Included,
            100,
            [0x72; 32],
            ratspeak_eth_gateway::TransactionStatusHead::new(103, [0x73; 32]).unwrap(),
            ratspeak_eth_gateway::TransactionStatusHead::new(102, [0x74; 32]).unwrap(),
            ratspeak_eth_gateway::TransactionStatusHead::new(101, [0x75; 32]).unwrap(),
        )
        .unwrap()));
    let (mut daemon, identity, _) = daemon(temp.path(), &requester_key, provider);
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let request_id = [0x70; 16];
    let request = packed_status_request(&requester_key, service_hash, request_id, tx_hash);
    let mut transport = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(&request, InboundRoute::Direct, 10, &mut transport),
        Ok(1)
    );
    let response = LxMessage::unpack(transport.sent[0].packed_message()).unwrap();
    let (_, attachment) = response.first_file_attachment().unwrap().unwrap();
    assert_eq!(attachment.len(), 226);
    assert_eq!(attachment[16], 9);
    assert_eq!(&attachment[17..33], &request_id);
    assert_eq!(&attachment[33..65], &tx_hash);

    // The completion/release are retained: an exact duplicate cannot trigger
    // another provider sample or amplify the already acknowledged response.
    let mut replay = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(&request, InboundRoute::Direct, 11, &mut replay),
        Ok(0)
    );
    assert!(replay.sent.is_empty());
}

#[test]
fn durable_field_outbox_permanent_provider_failure_returns_signed_exact_service_failure() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, identity, config) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let request_id = [0xa1; 16];
    let binding = OutboundMessageBinding::new(service_hash, REQUESTER, 1).unwrap();
    let profile = temp.path().join("field-profile");
    let mut field = EthereumNodeStore::open_in_profile(&profile).unwrap();
    field
        .create_evidence_request(OutboundEvidenceRequest::new(
            request_id,
            service_hash,
            MessagingEvidenceKind::ReceiptProof,
            [0xa2; 32],
            1024,
            100,
            10_000,
        ))
        .unwrap();
    let lease = field
        .lease_next_outbound_message(binding, 101, 60)
        .unwrap()
        .unwrap();
    field
        .settle_outbound_message_queued(binding, &lease, 102)
        .unwrap();

    let mut request = LxMessage::new(service_hash, REQUESTER, "", "", DeliveryMethod::Direct);
    request
        .set_file_attachment_field(
            ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME,
            lease.attachment(),
        )
        .unwrap();
    request.sign(&requester_key).unwrap();
    let mut transport = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(
            &request.pack().unwrap(),
            InboundRoute::Direct,
            103,
            &mut transport,
        ),
        Ok(1)
    );
    assert_eq!(transport.sent.len(), 1);

    let response = LxMessage::unpack(transport.sent[0].packed_message()).unwrap();
    assert_eq!(response.source_hash, service_hash);
    assert_eq!(response.destination_hash, REQUESTER);
    let service_private = identity.get_private_key().unwrap();
    let mut service_seed = [0; 32];
    service_seed.copy_from_slice(&service_private[32..]);
    assert!(
        response
            .clone()
            .verify(&Ed25519PrivateKey::from_bytes(&service_seed).public_key())
    );
    let (name, service_failure) = response.first_file_attachment().unwrap().unwrap();
    assert_eq!(name, ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME);

    assert_eq!(
        field
            .handle_attachment_from_trusted_lxmf_adapter(
                service_hash,
                response.source_hash,
                service_failure,
                104,
            )
            .unwrap(),
        NodeMessageOutcome::ServiceFailed
    );
    assert_eq!(
        field.message_request_status(request_id).unwrap(),
        Some(MessageRequestStatus::Cancelled)
    );
    assert_eq!(field.pending_message_evidence(request_id).unwrap(), None);
    assert_eq!(
        field
            .handle_attachment_from_trusted_lxmf_adapter(
                service_hash,
                response.source_hash,
                service_failure,
                105,
            )
            .unwrap(),
        NodeMessageOutcome::Duplicate
    );

    drop(field);
    drop(daemon);
    let mut restarted =
        GatewayDaemon::open(&config, &identity, FixtureProvider::accepted()).unwrap();
    let mut after_restart = RecordingTransport::default();
    assert_eq!(restarted.resume_once(106, &mut after_restart), Ok(0));
    let reopened = EthereumNodeStore::open_in_profile(&profile).unwrap();
    assert_eq!(
        reopened.message_request_status(request_id).unwrap(),
        Some(MessageRequestStatus::Cancelled)
    );
    assert_eq!(reopened.pending_message_evidence(request_id).unwrap(), None);
}

#[test]
fn spoofed_sender_and_wrong_destination_fail_closed() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let wrong_key = Ed25519PrivateKey::from_bytes(&[0x43; 32]);
    let (mut daemon, identity, _) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let mut transport = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(
            &packed_request(&wrong_key, service_hash, [1; 16]),
            InboundRoute::Direct,
            10,
            &mut transport,
        ),
        Err(DaemonError::MessageRejected)
    );
    assert_eq!(
        daemon.handle_packed(
            &packed_request(&requester_key, [0x99; 16], [2; 16]),
            InboundRoute::Direct,
            10,
            &mut transport,
        ),
        Err(DaemonError::MessageRejected)
    );
    assert!(transport.sent.is_empty());
}

#[test]
fn duplicate_and_lying_ack_do_not_change_protocol_result() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, identity, _) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let packed = packed_request(&requester_key, service_hash, [7; 16]);
    let mut transport = RecordingTransport {
        observation: Some(TransportObservation::LyingAcknowledgementForTest),
        ..RecordingTransport::default()
    };
    assert_eq!(
        daemon.handle_packed(&packed, InboundRoute::Direct, 10, &mut transport),
        Ok(1)
    );
    assert_eq!(
        daemon.handle_packed(&packed, InboundRoute::Direct, 11, &mut transport),
        Ok(0)
    );
    assert_eq!(transport.sent.len(), 1);
    let first = LxMessage::unpack(transport.sent[0].packed_message()).unwrap();
    assert!(first.first_file_attachment().unwrap().is_some());
}

#[test]
fn restart_resumes_deferred_and_does_not_repeat_acknowledged_output() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let identity = Identity::new();
    let config = config(temp.path(), &requester_key);
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let packed = packed_request(&requester_key, service_hash, [8; 16]);
    let mut transport = RecordingTransport::default();
    {
        let mut daemon = GatewayDaemon::open(
            &config,
            &identity,
            FixtureProvider::transient_then_accepted(),
        )
        .unwrap();
        assert_eq!(
            daemon.handle_packed(&packed, InboundRoute::Direct, 10, &mut transport),
            Ok(0)
        );
    }
    let mut restarted =
        GatewayDaemon::open(&config, &identity, FixtureProvider::accepted()).unwrap();
    assert_eq!(restarted.resume_once(40, &mut transport), Ok(1));
    drop(restarted);
    let mut completed =
        GatewayDaemon::open(&config, &identity, FixtureProvider::accepted()).unwrap();
    assert_eq!(completed.resume_once(41, &mut transport), Ok(0));
}

#[test]
fn idle_scheduler_is_silent() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, _, _) = daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let mut transport = RecordingTransport::default();
    assert_eq!(daemon.resume_once(10, &mut transport), Ok(0));
    assert!(transport.sent.is_empty());
}

#[test]
fn rejected_transport_observation_is_not_authoritative() {
    struct RejectingTransport(usize);
    impl OutboundLxmfTransport for RejectingTransport {
        fn send(
            &mut self,
            _message: SealedOutboundLxmf,
        ) -> Result<TransportObservation, DaemonError> {
            self.0 += 1;
            Ok(TransportObservation::Rejected)
        }
    }

    // Relay output contains one frame; this proves rejection is treated as a
    // transport failure and never as an authoritative provider result.
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, identity, _) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_hash =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&identity.hash));
    let mut transport = RejectingTransport(0);
    assert_eq!(
        daemon.handle_packed(
            &packed_request(&requester_key, service_hash, [0x22; 16]),
            InboundRoute::Direct,
            10,
            &mut transport,
        ),
        Err(DaemonError::TransportUnavailable)
    );
    assert_eq!(transport.0, 1);
}

#[test]
fn private_file_reader_rejects_permissions_symlinks_and_hardlinks() {
    let temp = private_temp();
    let file = temp.path().join("config.json");
    std::fs::write(&file, b"{}").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        read_private_regular_file(&file, 100),
        Err(DaemonError::InvalidFilesystemBoundary)
    );
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.path().join("config-link.json");
    symlink(&file, &link).unwrap();
    assert_eq!(
        read_private_regular_file(&link, 100),
        Err(DaemonError::InvalidFilesystemBoundary)
    );
    let hard = temp.path().join("config-hard.json");
    std::fs::hard_link(&file, &hard).unwrap();
    assert_eq!(
        read_private_regular_file(&file, 100),
        Err(DaemonError::InvalidFilesystemBoundary)
    );
}

#[test]
fn instance_lock_is_exclusive_and_recoverable() {
    let temp = private_temp();
    let path = temp.path().join("gateway.lock");
    let first = InstanceLock::acquire(&path).unwrap();
    assert!(matches!(
        InstanceLock::acquire(&path),
        Err(DaemonError::AlreadyRunning)
    ));
    drop(first);
    InstanceLock::acquire(&path).unwrap();
}

#[test]
fn service_identity_create_reload_and_symlink_rejection() {
    let temp = private_temp();
    let path = temp.path().join("service.identity");
    assert!(matches!(
        load_service_identity(&path),
        Err(DaemonError::InvalidFilesystemBoundary)
    ));
    assert!(!path.exists());
    let created = load_or_create_service_identity(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let loaded = load_or_create_service_identity(&path).unwrap();
    assert_eq!(created.hash, loaded.hash);
    assert_eq!(load_service_identity(&path).unwrap().hash, created.hash);
    let alias = temp.path().join("alias.identity");
    symlink(&path, &alias).unwrap();
    assert!(matches!(
        load_or_create_service_identity(&alias),
        Err(DaemonError::InvalidFilesystemBoundary)
    ));
}

#[test]
fn debug_output_redacts_paths_keys_and_endpoint() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let config = config(temp.path(), &requester_key);
    let debug = format!(
        "{config:?} {:?} {:?}",
        config.requesters[0], config.provider
    );
    assert!(!debug.contains(temp.path().to_str().unwrap()));
    assert!(!debug.contains("rpc.invalid"));
    assert!(!debug.contains(&config.requesters[0].ed25519_public_key));
}

#[test]
fn native_provider_type_has_concrete_complete_block_receipts() {
    type Expected = ratspeak_eth_gateway::LiveSepoliaGatewayProvider<
        ratspeak_eth_gateway::ReqwestBeaconHttpTransport,
        ratspeak_eth_gateway::ReqwestGatewayHttpTransport,
        ratspeak_eth_gateway::SystemUnixClock,
        ratspeak_eth_gateway::CompleteBlockReceiptProofBackend<
            ratspeak_eth_gateway::ReqwestGatewayHttpTransport,
        >,
    >;
    fn assert_loader_type(_: fn(&ProviderConfig) -> Result<Expected, DaemonError>) {}
    assert_loader_type(load_native_provider);
}

#[test]
fn native_provider_composes_without_reading_proof_fixtures() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let config = config(temp.path(), &requester_key);
    let provider = load_native_provider(&config.provider).unwrap();
    let debug = format!("{provider:?}");
    assert!(debug.contains("checkpoint-pinned"));
    assert!(!debug.contains("beacon.invalid"));
    assert!(!debug.contains("rpc.invalid"));
}

#[test]
fn static_proof_feed_fields_are_rejected_by_production_config() {
    let value = serde_json::json!({
        "checkpoint_root": hex::encode([0x44; 32]),
        "checkpoint_epoch": 1,
        "consensus_floor_path": "/private/consensus.floor",
        "beacon_rpc_endpoint": "https://beacon.invalid",
        "execution_rpc_endpoint": "https://rpc.invalid",
        "beacon_authorization_path": null,
        "execution_authorization_path": null,
        "consensus_bootstrap_path": "/private/bootstrap.ssz"
    });
    let error = serde_json::from_value::<ProviderConfig>(value).unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn production_provider_rejects_insecure_remote_endpoints() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let mut config = config(temp.path(), &requester_key);
    config.provider.beacon_rpc_endpoint = "http://192.0.2.1".into();
    assert!(matches!(
        load_native_provider(&config.provider),
        Err(DaemonError::ProviderUnavailable)
    ));

    config.provider.beacon_rpc_endpoint = "https://beacon.invalid".into();
    config.provider.execution_rpc_endpoint = "http://192.0.2.1".into();
    assert!(matches!(
        load_native_provider(&config.provider),
        Err(DaemonError::ProviderUnavailable)
    ));
}

#[test]
fn loopback_http_requires_explicit_development_opt_in() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let mut config = config(temp.path(), &requester_key);
    config.provider.beacon_rpc_endpoint = "http://127.0.0.1:5052".into();
    config.provider.execution_rpc_endpoint = "http://[::1]:8545".into();
    assert!(load_native_provider(&config.provider).is_err());
    config.provider.allow_loopback_http_for_development = true;
    assert!(load_native_provider(&config.provider).is_ok());

    config.provider.beacon_rpc_endpoint = "http://localhost:5052".into();
    assert!(load_native_provider(&config.provider).is_err());
}

#[test]
fn consensus_floor_is_durable_checkpoint_bound_and_monotonic() {
    let temp = private_temp();
    let path = temp.path().join("consensus.floor");
    let checkpoint = [0x44; 32];
    let first = VerifiedConsensusFloor::new(checkpoint, 100, [0x55; 32]).unwrap();
    let (mut sink, restored) = ConsensusFloorFile::open(path.clone(), checkpoint).unwrap();
    assert_eq!(restored, None);
    sink.commit(first).unwrap();
    assert_eq!(
        load_consensus_floor(&path, checkpoint).unwrap(),
        Some(first)
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let rollback = VerifiedConsensusFloor::new(checkpoint, 99, [0x56; 32]).unwrap();
    assert_eq!(
        sink.commit(rollback),
        Err(GatewayProviderFailure::Permanent)
    );
    let conflict = VerifiedConsensusFloor::new(checkpoint, 100, [0x57; 32]).unwrap();
    assert_eq!(
        sink.commit(conflict),
        Err(GatewayProviderFailure::Permanent)
    );
    assert_eq!(
        load_consensus_floor(&path, checkpoint).unwrap(),
        Some(first)
    );
    assert!(matches!(
        load_consensus_floor(&path, [0x99; 32]),
        Err(DaemonError::ProviderUnavailable)
    ));
}

#[test]
fn corrupt_or_aliased_consensus_floor_fails_closed() {
    let temp = private_temp();
    let path = temp.path().join("consensus.floor");
    std::fs::write(&path, b"truncated").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        load_consensus_floor(&path, [0x44; 32]),
        Err(DaemonError::ProviderUnavailable)
    ));

    std::fs::remove_file(&path).unwrap();
    let target = temp.path().join("target.floor");
    std::fs::write(&target, vec![0_u8; CONSENSUS_FLOOR_BYTES as usize]).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &path).unwrap();
    assert!(matches!(
        load_consensus_floor(&path, [0x44; 32]),
        Err(DaemonError::InvalidFilesystemBoundary)
    ));
}

#[test]
fn same_length_consensus_floor_corruption_fails_closed() {
    let temp = private_temp();
    let path = temp.path().join("consensus.floor");
    let checkpoint = [0x44; 32];
    let floor = VerifiedConsensusFloor::new(checkpoint, 100, [0x55; 32]).unwrap();
    persist_consensus_floor(&path, floor).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[42] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        load_consensus_floor(&path, checkpoint),
        Err(DaemonError::ProviderUnavailable)
    ));
}

#[test]
fn consensus_floor_path_has_single_writer_ownership() {
    let temp = private_temp();
    let path = temp.path().join("consensus.floor");
    let checkpoint = [0x44; 32];
    let (first, _) = ConsensusFloorFile::open(path.clone(), checkpoint).unwrap();
    assert!(matches!(
        ConsensusFloorFile::open(path.clone(), checkpoint),
        Err(DaemonError::AlreadyRunning)
    ));
    drop(first);
    assert!(ConsensusFloorFile::open(path, checkpoint).is_ok());
}

#[test]
fn consensus_floor_detects_valid_but_rolled_back_disk_state() {
    let temp = private_temp();
    let path = temp.path().join("consensus.floor");
    let checkpoint = [0x44; 32];
    let first = VerifiedConsensusFloor::new(checkpoint, 100, [0x55; 32]).unwrap();
    let (mut sink, _) = ConsensusFloorFile::open(path.clone(), checkpoint).unwrap();
    sink.commit(first).unwrap();

    let rolled_back = VerifiedConsensusFloor::new(checkpoint, 99, [0x54; 32]).unwrap();
    persist_consensus_floor(&path, rolled_back).unwrap();
    let candidate = VerifiedConsensusFloor::new(checkpoint, 101, [0x56; 32]).unwrap();
    assert_eq!(
        sink.commit(candidate),
        Err(GatewayProviderFailure::Permanent)
    );
    assert_eq!(
        load_consensus_floor(&path, checkpoint).unwrap(),
        Some(rolled_back)
    );
}

#[test]
fn consensus_floor_cannot_alias_other_daemon_state() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let mut config = config(temp.path(), &requester_key);
    for protected in [
        config.service_identity_path.clone(),
        config.durable_gateway_db.clone(),
        config.instance_lock_path.clone(),
    ] {
        config.provider.consensus_floor_path = protected;
        assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));
    }
    let authorization = temp.path().join("provider.authorization");
    config.provider.consensus_floor_path = authorization.clone();
    config.provider.execution_authorization_path = Some(authorization);
    assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));

    config.provider.execution_authorization_path = None;
    let floor = temp.path().join("another.floor");
    config.provider.consensus_floor_path = floor.clone();
    config.service_identity_path = consensus_floor_lock_path(&floor);
    assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));
}

#[test]
fn provider_authorization_reader_is_private_bounded_and_redacted() {
    let temp = private_temp();
    let path = temp.path().join("rpc.authorization");
    std::fs::write(&path, b"Bearer private-test-token\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let authorization = load_operator_authorization(Some(&path)).unwrap().unwrap();
    let debug = format!("{authorization:?}");
    assert_eq!(debug, "OperatorAuthorization([REDACTED])");
    assert!(!debug.contains("private-test-token"));

    std::fs::write(&path, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(matches!(
        load_operator_authorization(Some(&path)),
        Err(DaemonError::InvalidFilesystemBoundary)
    ));
}

#[test]
fn propagation_requires_exact_node_and_requester_full_keys() {
    let temp = private_temp();
    let requester = Identity::new();
    let requester_private = requester.get_private_key().unwrap();
    let mut requester_seed = [0; 32];
    requester_seed.copy_from_slice(&requester_private[32..]);
    let requester_signing = Ed25519PrivateKey::from_bytes(&requester_seed);
    let node = Identity::new();
    let node_destination =
        Destination::hash_from_name_and_identity(LXMF_PROPAGATION_ASPECT, Some(&node.hash));
    let mut config = config(temp.path(), &requester_signing);
    config.propagation = Some(PropagationConfig {
        node_destination_hash: hex::encode(node_destination),
        node_rns_public_key: hex::encode(node.get_public_key()),
        poll_interval_seconds: 60,
        delivery_limit_kb: 8,
        maximum_messages_per_poll: 2,
        outbound_fallback: true,
        node_transfer_limit_kb: 64,
        node_stamp_cost: 0,
    });
    assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));

    config.requesters[0].rns_public_key = Some(hex::encode(requester.get_public_key()));
    assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));
    config.requesters[0].source_hash = hex::encode(Destination::hash_from_name_and_identity(
        LXMF_DELIVERY_ASPECT,
        Some(&requester.hash),
    ));
    assert_eq!(config.validate(), Ok(()));

    config.propagation.as_mut().unwrap().node_destination_hash = hex::encode([0x88; 16]);
    assert_eq!(config.validate(), Err(DaemonError::InvalidConfiguration));
}

#[test]
fn configured_fallback_is_encrypted_for_exact_requester_and_targets_only_relay() {
    let temp = private_temp();
    let requester = Identity::new();
    let requester_private = requester.get_private_key().unwrap();
    let mut requester_seed = [0; 32];
    requester_seed.copy_from_slice(&requester_private[32..]);
    let requester_signing = Ed25519PrivateKey::from_bytes(&requester_seed);
    let requester_destination =
        Destination::hash_from_name_and_identity(LXMF_DELIVERY_ASPECT, Some(&requester.hash));
    let node = Identity::new();
    let node_destination =
        Destination::hash_from_name_and_identity(LXMF_PROPAGATION_ASPECT, Some(&node.hash));
    let service_identity = Identity::new();
    let mut config = config(temp.path(), &requester_signing);
    config.requesters[0] = RequesterConfig {
        source_hash: hex::encode(requester_destination),
        ed25519_public_key: hex::encode(requester_signing.public_key().to_bytes()),
        rns_public_key: Some(hex::encode(requester.get_public_key())),
        contact_card_path: None,
    };
    config.propagation = Some(PropagationConfig {
        node_destination_hash: hex::encode(node_destination),
        node_rns_public_key: hex::encode(node.get_public_key()),
        poll_interval_seconds: 60,
        delivery_limit_kb: 8,
        maximum_messages_per_poll: 2,
        outbound_fallback: true,
        node_transfer_limit_kb: 64,
        node_stamp_cost: 0,
    });
    let service_destination = Destination::hash_from_name_and_identity(
        LXMF_DELIVERY_ASPECT,
        Some(&service_identity.hash),
    );
    let mut request = LxMessage::new(
        service_destination,
        requester_destination,
        "",
        "",
        DeliveryMethod::Direct,
    );
    request
        .set_file_attachment_field(
            ratspeak_eth_gateway::GATEWAY_LXMF_ATTACHMENT_NAME,
            &relay_wire([0x91; 16], 10_000),
        )
        .unwrap();
    request.sign(&requester_signing).unwrap();
    let mut daemon =
        GatewayDaemon::open(&config, &service_identity, FixtureProvider::accepted()).unwrap();
    let mut transport = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(
            &request.pack().unwrap(),
            InboundRoute::Direct,
            10,
            &mut transport,
        ),
        Ok(1)
    );
    let direct = &transport.sent[0];
    assert_eq!(direct.destination_hash(), requester_destination);
    let fallback = direct.propagation_fallback().unwrap();
    assert_eq!(fallback.destination_hash(), node_destination);
    assert_ne!(fallback.packed_message(), direct.packed_message());
    assert!(fallback.propagation_fallback().is_none());
    let (_, entries) = LxMessage::unpack_propagation_wrapper(fallback.packed_message()).unwrap();
    assert_eq!(entries.len(), 1);
    let propagated = &entries[0];
    let encrypted_end = propagated.len() - lxmf_core::constants::STAMP_SIZE;
    let plaintext = requester
        .decrypt(&propagated[16..encrypted_end], None, false)
        .unwrap();
    let mut reconstructed = propagated[..16].to_vec();
    reconstructed.extend_from_slice(&plaintext);
    let unpacked = LxMessage::unpack(&reconstructed).unwrap();
    assert_eq!(unpacked.destination_hash, requester_destination);
    let service_private = service_identity.get_private_key().unwrap();
    let mut service_seed = [0; 32];
    service_seed.copy_from_slice(&service_private[32..]);
    assert!(
        unpacked
            .clone()
            .verify(&Ed25519PrivateKey::from_bytes(&service_seed).public_key())
    );
}

#[test]
fn downloaded_ciphertext_enters_the_same_authenticated_propagated_gate() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, service_identity, _) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_destination = Destination::hash_from_name_and_identity(
        LXMF_DELIVERY_ASPECT,
        Some(&service_identity.hash),
    );
    let packed = packed_request(&requester_key, service_destination, [0x92; 16]);
    let service_public = Identity::from_public_key(&service_identity.get_public_key()).unwrap();
    let mut downloaded = service_destination.to_vec();
    downloaded.extend_from_slice(&service_public.encrypt(&packed[16..], None).unwrap());

    let decoded = crate::propagation::decode_download_batch(
        &service_identity,
        service_destination,
        8 * 1024,
        1,
        vec![downloaded],
    );
    assert_eq!(decoded.len(), 1);
    let mut transport = RecordingTransport::default();
    assert_eq!(
        daemon.handle_packed(&decoded[0], InboundRoute::Propagated, 10, &mut transport,),
        Ok(1)
    );
}

fn link_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    packet_type: rns_wire::flags::PacketType,
    payload: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(payload);
    Bytes::from(raw)
}

fn encode_value(value: rmpv::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).unwrap();
    bytes
}

#[test]
fn real_propagation_client_pickup_reaches_durable_authenticated_admission() {
    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x42; 32]);
    let (mut daemon, service_identity, _) =
        daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let service_destination = Destination::hash_from_name_and_identity(
        LXMF_DELIVERY_ASPECT,
        Some(&service_identity.hash),
    );
    let packed = packed_request(&requester_key, service_destination, [0x93; 16]);
    let service_public = Identity::from_public_key(&service_identity.get_public_key()).unwrap();
    let mut downloaded = service_destination.to_vec();
    downloaded.extend_from_slice(&service_public.encrypt(&packed[16..], None).unwrap());
    let transient_id = rns_crypto::sha::full_hash(&downloaded);

    let node_identity = Identity::new();
    let node_destination = Destination::hash_from_name_and_identity(
        LXMF_PROPAGATION_ASPECT,
        Some(&node_identity.hash),
    );
    let validated = ValidatedPropagationConfig {
        node_destination_hash: node_destination,
        node_rns_public_key: node_identity.get_public_key(),
        poll_interval: Duration::from_secs(5),
        delivery_limit_kb: 8,
        maximum_messages_per_poll: 1,
        outbound_fallback: false,
        node_transfer_limit_kb: 64,
        node_stamp_cost: 0,
    };
    let (transport_tx, mut transport_rx) = tokio::sync::mpsc::channel(256);
    let started = Instant::now();
    let mut pickup = crate::propagation::ConfiguredPropagationClient::new(
        transport_tx,
        service_identity.clone(),
        service_destination,
        &validated,
        started,
    )
    .unwrap();
    assert!(pickup.tick(started + Duration::from_secs(5)).is_none());

    let mut event_tx = None;
    let mut link_request = None;
    while let Ok(command) = transport_rx.try_recv() {
        match command {
            TransportMessage::RegisterDestination { delivery_tx, .. } => event_tx = delivery_tx,
            TransportMessage::Outbound(request) => link_request = Some(request),
            _ => {}
        }
    }
    let event_tx = event_tx.unwrap();
    let request = link_request.unwrap();
    let (_, request_offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
    let node_private = node_identity.get_private_key().unwrap();
    let mut node_seed = [0; 32];
    node_seed.copy_from_slice(&node_private[32..]);
    let node_signing = Ed25519PrivateKey::from_bytes(&node_seed);
    let (mut responder, proof) = Link::new_responder(
        &request.raw[request_offset..],
        &node_signing,
        node_destination,
        1,
    )
    .unwrap();
    let link_id = responder.link_id;
    event_tx
        .try_send(DestinationEvent::InboundPacket {
            raw: link_packet(
                link_id,
                rns_wire::context::PacketContext::Lrproof,
                rns_wire::flags::PacketType::Proof,
                &proof,
            ),
            interface_id: 7,
            metrics: PacketMetrics::default(),
        })
        .unwrap();

    let mut request_phase = 0_u8;
    let mut decoded = None;
    for step in 0..20 {
        decoded = pickup.tick(started + Duration::from_secs(6 + step));
        if decoded.is_some() {
            break;
        }
        while let Ok(command) = transport_rx.try_recv() {
            match command {
                TransportMessage::BindLinkEndpoint { result_tx, .. } => {
                    result_tx.send(LinkEndpointBindResult::Bound).unwrap();
                }
                TransportMessage::SendLinkEndpoint {
                    request, result_tx, ..
                } => {
                    result_tx.send(LinkEndpointSendResult::Sent).unwrap();
                    let (header, offset) =
                        rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
                    match header.context {
                        rns_wire::context::PacketContext::Lrrtt => {
                            responder
                                .receive_rtt_packet(&request.raw[offset..])
                                .unwrap();
                        }
                        rns_wire::context::PacketContext::Request => {
                            let (request_id, _, _, _) =
                                responder.handle_request(&request.raw[offset..]).unwrap();
                            let body = if request_phase == 0 {
                                request_phase = 1;
                                encode_value(rmpv::Value::Array(vec![rmpv::Value::Binary(
                                    transient_id.to_vec(),
                                )]))
                            } else {
                                encode_value(rmpv::Value::Array(vec![rmpv::Value::Binary(
                                    downloaded.clone(),
                                )]))
                            };
                            let response = responder.create_response(&request_id, &body).unwrap();
                            event_tx
                                .try_send(DestinationEvent::InboundPacket {
                                    raw: link_packet(
                                        link_id,
                                        rns_wire::context::PacketContext::Response,
                                        rns_wire::flags::PacketType::Data,
                                        &response,
                                    ),
                                    interface_id: 7,
                                    metrics: PacketMetrics::default(),
                                })
                                .unwrap();
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    let decoded = decoded.expect("relay returns one completed batch");
    assert_eq!(decoded.len(), 1);
    let mut outbound = RecordingTransport::default();
    assert_eq!(
        daemon.handle_propagated_packed(&decoded[0], 10, &mut outbound),
        PropagatedMessageDisposition::Resolved
    );
    assert_eq!(outbound.sent.len(), 1);
    assert!(pickup.resolve_batch(
        crate::propagation::DownloadBatchResolution::Resolved,
        started + Duration::from_secs(30),
    ));

    let mut purge = None;
    while let Ok(command) = transport_rx.try_recv() {
        if let TransportMessage::SendLinkEndpoint {
            request, result_tx, ..
        } = command
        {
            result_tx.send(LinkEndpointSendResult::Sent).unwrap();
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
            if header.context == rns_wire::context::PacketContext::Request {
                let (request_id, _, _, request_data) =
                    responder.handle_request(&request.raw[offset..]).unwrap();
                purge = Some((request_id, request_data));
                break;
            }
        }
    }
    let (purge_request_id, purge_data) = purge.expect("post-admission purge request");
    let purge_value = rmpv::decode::read_value(&mut purge_data.as_slice()).unwrap();
    assert_eq!(
        purge_value,
        rmpv::Value::Array(vec![
            rmpv::Value::Nil,
            rmpv::Value::Array(vec![rmpv::Value::Binary(transient_id.to_vec())]),
        ])
    );

    let purge_response = responder
        .create_response(&purge_request_id, &encode_value(rmpv::Value::Nil))
        .unwrap();
    event_tx
        .try_send(DestinationEvent::InboundPacket {
            raw: link_packet(
                link_id,
                rns_wire::context::PacketContext::Response,
                rns_wire::flags::PacketType::Data,
                &purge_response,
            ),
            interface_id: 7,
            metrics: PacketMetrics::default(),
        })
        .unwrap();
    assert!(pickup.tick(started + Duration::from_secs(31)).is_none());
    assert_eq!(
        daemon.handle_propagated_packed(&decoded[0], 11, &mut outbound),
        PropagatedMessageDisposition::Resolved
    );
    assert_eq!(
        outbound.sent.len(),
        1,
        "purge completion and duplicate pickup may not replay output"
    );
}

#[test]
fn propagated_safe_rejects_purge_but_pre_admission_storage_ambiguity_retries() {
    assert_eq!(
        classify_propagated_service_error(GatewayLxmfServiceError::Admission(
            GatewayAdmissionError::Storage,
        )),
        PropagatedMessageDisposition::Retry
    );
    assert_eq!(
        classify_propagated_service_error(GatewayLxmfServiceError::Admission(
            GatewayAdmissionError::InvalidState,
        )),
        PropagatedMessageDisposition::Retry
    );
    assert_eq!(
        classify_propagated_service_error(GatewayLxmfServiceError::Admission(
            GatewayAdmissionError::ReplayConflict,
        )),
        PropagatedMessageDisposition::Resolved
    );

    let temp = private_temp();
    let requester_key = Ed25519PrivateKey::from_bytes(&[0x47; 32]);
    let (mut daemon, _, _) = daemon(temp.path(), &requester_key, FixtureProvider::accepted());
    let mut outbound = RecordingTransport::default();
    assert_eq!(
        daemon.handle_propagated_packed(b"not an LXMF message", 10, &mut outbound),
        PropagatedMessageDisposition::Resolved
    );
    assert!(outbound.sent.is_empty());
}
