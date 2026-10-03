use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratspeak_eth_gateway_daemon::propagation::{
    ConfiguredPropagationClient, DownloadBatchResolution,
};
use ratspeak_eth_gateway_daemon::{
    DaemonError, GatewayDaemon, GatewayDaemonConfig, InboundRoute, InstanceLock,
    NativeSepoliaProvider, OutboundLxmfTransport, PropagatedMessageDisposition, SealedOutboundLxmf,
    TransportObservation, ValidatedPropagationConfig, install_private_process_umask,
    load_native_provider, load_or_create_service_identity, load_service_identity,
    validate_private_directory,
};
use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_link::link::ResourceStrategy;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::prelude::{
    DestinationAnnounceOptions, DestinationRuntimeOptions, LinkConnectOptions,
    ResourceAcceptPolicy, ResourceOptions, ReticulumHandle,
};

const MAX_INBOUND_LXMF_BYTES: usize = 8 * 1024;
const SERVICE_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15 * 60);
const RESPONSE_ROUTE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);

struct RuntimeResourceSender {
    handle: ReticulumHandle,
    service_identity: Identity,
    maximum_attempts: u8,
    retry_delay: Duration,
}

trait ExactRnsSender {
    fn send_exact(
        &mut self,
        message: SealedOutboundLxmf,
    ) -> Result<TransportObservation, DaemonError>;
}

struct RnsOutbound<S> {
    sender: S,
}

impl<S: ExactRnsSender> OutboundLxmfTransport for RnsOutbound<S> {
    fn send(&mut self, message: SealedOutboundLxmf) -> Result<TransportObservation, DaemonError> {
        let fallback = message.propagation_fallback().cloned();
        send_with_explicit_fallback(message, fallback, |message| self.sender.send_exact(message))
    }
}

/// Returns a response on the already authenticated inbound Link. This avoids
/// requiring a separately announced reverse path for ordinary request/reply
/// traffic. If the Link closes, the durable scheduler retains its existing
/// bounded path-discovery/propagation retry behavior.
struct ExistingLinkOutbound {
    handle: rns_runtime::destination_runtime::DestinationHandle,
    link_id: [u8; 16],
}

impl OutboundLxmfTransport for ExistingLinkOutbound {
    fn send(&mut self, message: SealedOutboundLxmf) -> Result<TransportObservation, DaemonError> {
        let handle = self.handle.clone();
        let link_id = self.link_id;
        let payload = message.packed_message().to_vec();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                handle
                    // Preserve the established Link for a delayed gateway
                    // response, but do not force a tiny manifest through the
                    // Resource protocol. `send_link_payload` uses encrypted
                    // Link DATA below the MDU and a Resource otherwise; both
                    // are received by Ratspeak's existing Direct LXMF path.
                    .send_link_payload(link_id, payload, false)
                    .await
                    .map(|_| TransportObservation::AcceptedForDelivery)
                    .map_err(|_| DaemonError::TransportUnavailable)
            })
        })
    }
}

fn send_with_explicit_fallback<M, O, E>(
    primary: M,
    fallback: Option<M>,
    mut send: impl FnMut(M) -> Result<O, E>,
) -> Result<O, E> {
    match send(primary) {
        Ok(observation) => Ok(observation),
        Err(error) => match fallback {
            Some(fallback) => send(fallback),
            None => Err(error),
        },
    }
}

fn handle_scheduled_resume(result: Result<usize, DaemonError>) -> Result<(), DaemonError> {
    match result {
        Ok(_) => Ok(()),
        Err(DaemonError::TransportUnavailable) => {
            // The durable service already consumed one bounded release attempt.
            // A missing return route must not terminate request admission or
            // prevent later requests from being processed.
            tracing::warn!(
                class = "response_transport_unavailable",
                "Ethereum gateway response handoff was deferred"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

impl ExactRnsSender for RuntimeResourceSender {
    fn send_exact(
        &mut self,
        message: SealedOutboundLxmf,
    ) -> Result<TransportObservation, DaemonError> {
        let handle = self.handle.clone();
        let identity = self.service_identity.clone();
        let maximum_attempts = self.maximum_attempts;
        let retry_delay = self.retry_delay;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                for attempt in 0..maximum_attempts {
                    let result = async {
                        handle
                            .await_path(
                                message.destination_hash(),
                                RESPONSE_ROUTE_DISCOVERY_TIMEOUT,
                            )
                            .await
                            .map_err(|_| DaemonError::TransportUnavailable)?;
                        let session = handle
                            .connect_link(
                                message.destination_hash(),
                                identity.clone(),
                                LinkConnectOptions {
                                    identify: true,
                                    client_label: "ratspeak-ethereum-gateway".to_string(),
                                    ..LinkConnectOptions::default()
                                },
                            )
                            .await
                            .map_err(|_| DaemonError::TransportUnavailable)?;
                        let transfer = session
                            .handle
                            .send_resource_bytes(
                                message.packed_message().to_vec(),
                                ResourceOptions {
                                    auto_compress: false,
                                    metadata: None,
                                },
                            )
                            .await
                            .map_err(|_| DaemonError::TransportUnavailable)?;
                        let result = transfer
                            .concluded()
                            .await
                            .map_err(|_| DaemonError::TransportUnavailable);
                        session.handle.close().await;
                        result.map(|_| TransportObservation::AcceptedForDelivery)
                    }
                    .await;
                    if result.is_ok() || attempt + 1 == maximum_attempts {
                        return result;
                    }
                    tokio::time::sleep(retry_delay).await;
                }
                Err(DaemonError::TransportUnavailable)
            })
        })
    }
}

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    if let Err(error) = run() {
        eprintln!("ratspeak Ethereum gateway terminated: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), DaemonError> {
    install_private_process_umask();
    let (config_path, mode) = parse_command(std::env::args_os().skip(1))?;
    let config = GatewayDaemonConfig::load(&config_path)?;
    validate_private_directory(&config.rns_config_dir)?;
    if mode == CommandMode::PrintPublicCard {
        let identity = load_service_identity(&config.service_identity_path)?;
        println!("{}", public_gateway_card(&identity)?);
        return Ok(());
    }
    if mode == CommandMode::PrintContactCard {
        let identity = load_service_identity(&config.service_identity_path)?;
        println!("{}", public_gateway_contact_card(&identity)?);
        return Ok(());
    }
    let _instance = InstanceLock::acquire(&config.instance_lock_path)?;
    let identity = load_or_create_service_identity(&config.service_identity_path)?;
    let propagation_config = config.validated_propagation()?;
    let provider = load_native_provider(&config.provider)?;
    let mut daemon = GatewayDaemon::open(&config, &identity, provider)?;

    // Reqwest's blocking clients own an internal Tokio runtime. Construct and
    // ultimately drop the native provider outside our asynchronous runtime;
    // dropping it from an async context panics even during orderly shutdown.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| DaemonError::TransportUnavailable)?;
    let result = runtime.block_on(run_async(
        &config,
        &identity,
        propagation_config,
        &mut daemon,
    ));
    drop(runtime);
    result
}

async fn run_async(
    config: &GatewayDaemonConfig,
    identity: &Identity,
    propagation_config: Option<ValidatedPropagationConfig>,
    daemon: &mut GatewayDaemon<NativeSepoliaProvider>,
) -> Result<(), DaemonError> {
    let config_dir = config
        .rns_config_dir
        .to_str()
        .ok_or(DaemonError::InvalidConfiguration)?;
    let shutdown = ShutdownSignal::new();
    let _signals = install_signal_handlers(shutdown.clone());
    let runtime = rns_runtime::prelude::init(
        Some(config_dir),
        None,
        shutdown.clone(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .map_err(|_| DaemonError::TransportUnavailable)?;

    let mut destination = runtime
        .register_destination(
            identity.clone(),
            "lxmf.delivery".to_string(),
            DestinationRuntimeOptions {
                resource_strategy: ResourceStrategy::AcceptApp,
                resource_accept: Some(ResourceAcceptPolicy::new(move |_, advertisement| {
                    advertisement.data_size <= MAX_INBOUND_LXMF_BYTES
                        && !advertisement.flags.has_metadata
                })),
                // The configured LXMF source hash is a destination hash, not a
                // Reticulum identity hash. Exact Ed25519 re-verification occurs
                // only after bounded reassembly; do not conflate the two.
                ..DestinationRuntimeOptions::default()
            },
        )
        .await
        .map_err(|_| DaemonError::TransportUnavailable)?;
    let mut outbound = RnsOutbound {
        sender: RuntimeResourceSender {
            handle: runtime.clone(),
            service_identity: identity.clone(),
            maximum_attempts: config.policy.maximum_outbound_attempts,
            retry_delay: Duration::from_millis(config.policy.outbound_retry_delay_ms),
        },
    };
    let service_destination_hash =
        Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash));
    destination
        .handle
        .announce(DestinationAnnounceOptions::default())
        .await
        .map_err(|_| DaemonError::TransportUnavailable)?;
    let mut propagation = propagation_config
        .as_ref()
        .map(|config| {
            ConfiguredPropagationClient::new(
                runtime.transport_tx.clone(),
                identity.clone(),
                service_destination_hash,
                config,
                Instant::now(),
            )
        })
        .transpose()?;
    let mut scheduler = tokio::time::interval(daemon.scheduler_interval());
    scheduler.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut announce_scheduler = tokio::time::interval(SERVICE_ANNOUNCE_INTERVAL);
    announce_scheduler.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Do not immediately poll retained state twice during startup.
    scheduler.tick().await;
    // The destination was announced explicitly above; consume the interval's
    // immediate tick so constrained transports are not sent a duplicate.
    announce_scheduler.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            packet = destination.events.packets.recv() => {
                let Some(packet) = packet else { break };
                // Native RPC adapters are deliberately blocking. Keep their
                // internal reqwest runtime outside Tokio's asynchronous
                // execution context or reqwest will panic while dropping it.
                let _ = tokio::task::block_in_place(|| {
                    daemon.handle_packed(
                        &packet.data,
                        InboundRoute::Opportunistic,
                        now_unix(),
                        &mut outbound,
                    )
                });
            }
            packet = destination.events.link_packets.recv() => {
                let Some((bytes, link_id)) = packet else { break };
                if bytes.len() <= MAX_INBOUND_LXMF_BYTES {
                    let mut response = ExistingLinkOutbound {
                        handle: destination.handle.clone(),
                        link_id,
                    };
                    let _ = tokio::task::block_in_place(|| {
                        daemon.handle_packed(
                            &bytes,
                            InboundRoute::Direct,
                            now_unix(),
                            &mut response,
                        )
                    });
                }
            }
            resource = destination.events.resource_completions.recv() => {
                let Some(resource) = resource else { break };
                if resource.data.len() <= MAX_INBOUND_LXMF_BYTES && resource.metadata.is_none() {
                    let mut response = ExistingLinkOutbound {
                        handle: destination.handle.clone(),
                        link_id: resource.link_id,
                    };
                    let _ = tokio::task::block_in_place(|| {
                        daemon.handle_packed(
                            &resource.data,
                            InboundRoute::Direct,
                            now_unix(),
                            &mut response,
                        )
                    });
                }
            }
            _ = scheduler.tick() => {
                // The service consumes a durable bounded handoff attempt before
                // returning bytes. A supervisor restart may retry an ambiguous
                // handoff, but cannot reset the per-result release budget.
                handle_scheduled_resume(tokio::task::block_in_place(|| {
                    daemon.resume_once(now_unix(), &mut outbound)
                }))?;
                if let Some(propagation) = propagation.as_mut() {
                    let batch_now = Instant::now();
                    if let Some(batch) = propagation.tick(batch_now) {
                        let mut resolution = DownloadBatchResolution::Resolved;
                        for packed in batch {
                            if tokio::task::block_in_place(|| {
                                daemon.handle_propagated_packed(
                                    &packed,
                                    now_unix(),
                                    &mut outbound,
                                )
                            }) == PropagatedMessageDisposition::Retry
                            {
                                resolution = DownloadBatchResolution::Retry;
                                break;
                            }
                        }
                        propagation.resolve_batch(resolution, batch_now);
                    }
                }
            }
            _ = announce_scheduler.tick() => {
                destination
                    .handle
                    .announce(DestinationAnnounceOptions::default())
                    .await
                    .map_err(|_| DaemonError::TransportUnavailable)?;
            }
        }
    }

    if let Some(propagation) = propagation.as_mut() {
        propagation.cancel();
    }

    destination
        .close()
        .await
        .map_err(|_| DaemonError::TransportUnavailable)?;
    runtime.shutdown_and_wait().await;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandMode {
    Serve,
    PrintPublicCard,
    PrintContactCard,
}

fn parse_command(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(PathBuf, CommandMode), DaemonError> {
    let flag = args.next().ok_or(DaemonError::InvalidConfiguration)?;
    let path = args.next().ok_or(DaemonError::InvalidConfiguration)?;
    if flag != "--config" {
        return Err(DaemonError::InvalidConfiguration);
    }
    let mode = match args.next() {
        None => CommandMode::Serve,
        Some(flag) if flag == "--print-public-card" && args.next().is_none() => {
            CommandMode::PrintPublicCard
        }
        Some(flag) if flag == "--print-contact-card" && args.next().is_none() => {
            CommandMode::PrintContactCard
        }
        _ => return Err(DaemonError::InvalidConfiguration),
    };
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(DaemonError::InvalidConfiguration);
    }
    Ok((path, mode))
}

fn public_gateway_card(identity: &Identity) -> Result<String, DaemonError> {
    use base64::Engine;
    let public_key = identity.get_public_key();
    let destination =
        Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash));
    Identity::from_public_key(&public_key)
        .ok()
        .filter(|public| {
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&public.hash))
                == destination
        })
        .ok_or(DaemonError::IdentityUnavailable)?;
    Ok(format!(
        "RSEG1:sepolia:{}:{}",
        hex::encode(destination),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
    ))
}

fn public_gateway_contact_card(identity: &Identity) -> Result<String, DaemonError> {
    use base64::Engine;
    let public_key = identity.get_public_key();
    let verified =
        Identity::from_public_key(&public_key).map_err(|_| DaemonError::IdentityUnavailable)?;
    if verified.hash != identity.hash {
        return Err(DaemonError::IdentityUnavailable);
    }
    let destination =
        Destination::hash_from_name_and_identity("lxmf.delivery", Some(&identity.hash));
    let name = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode("Ratspeak Sepolia Service".as_bytes());
    Ok(format!(
        "RSCP1:{}:{}:{}:{}",
        name,
        hex::encode(destination),
        hex::encode(identity.hash),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
    ))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::PermissionsExt;

    use lxmf_core::message_api::{DeliveryMethod, LxMessage};
    use ratspeak_eth_gateway::{
        AcceptedEvidenceRequest, AcceptedSignedRelay, GatewayBundle, GatewayExecutionProvider,
        GatewayProviderFailure, RelayProviderObservation, RelayProviderStatus,
    };
    use ratspeak_eth_gateway_daemon::{
        DaemonError, DaemonPolicyConfig, GatewayDaemon, GatewayDaemonConfig, InboundRoute,
        InstanceLock, OutboundLxmfTransport, PropagationConfig, ProviderConfig, RequesterConfig,
        SealedOutboundLxmf, TransportObservation, load_or_create_service_identity,
        load_service_identity,
    };
    use ratspeak_eth_verifier::SEPOLIA_CHAIN_ID;
    use rns_crypto::ed25519::Ed25519PrivateKey;
    use rns_identity::destination::Destination;
    use rns_identity::identity::Identity;

    use super::{
        CommandMode, ExactRnsSender, RnsOutbound, SERVICE_ANNOUNCE_INTERVAL,
        handle_scheduled_resume, parse_command, public_gateway_card, public_gateway_contact_card,
    };

    #[test]
    fn service_announces_after_registration_and_reannounces_at_low_duty_cycle() {
        assert_eq!(
            SERVICE_ANNOUNCE_INTERVAL,
            std::time::Duration::from_secs(15 * 60)
        );
        let source = include_str!("main.rs");
        let runtime = &source[source.find("async fn run_async(").unwrap()..];
        let registered = runtime.find(".register_destination(").unwrap();
        let announced = runtime
            .find(".announce(DestinationAnnounceOptions::default())")
            .unwrap();
        let event_loop = runtime.find("loop {").unwrap();
        assert!(registered < announced && announced < event_loop);
        assert!(runtime.contains("announce_scheduler.tick()"));
    }

    #[test]
    fn operator_query_is_strict_and_outputs_only_the_public_gateway_card() {
        let path = std::path::PathBuf::from("/private/gateway.json");
        assert_eq!(
            parse_command(
                ["--config", "/private/gateway.json", "--print-contact-card"]
                    .into_iter()
                    .map(Into::into),
            )
            .unwrap(),
            (path.clone(), CommandMode::PrintContactCard)
        );
        assert_eq!(
            parse_command(
                ["--config", "/private/gateway.json", "--print-public-card"]
                    .into_iter()
                    .map(Into::into),
            )
            .unwrap(),
            (path.clone(), CommandMode::PrintPublicCard)
        );
        assert_eq!(
            parse_command(
                ["--config", "/private/gateway.json"]
                    .into_iter()
                    .map(Into::into)
            )
            .unwrap(),
            (path, CommandMode::Serve)
        );
        for args in [
            vec!["--config", "relative.json", "--print-public-card"],
            vec!["--print-public-card", "/private/gateway.json"],
            vec!["--config", "/private/gateway.json", "--unknown"],
            vec![
                "--config",
                "/private/gateway.json",
                "--print-public-card",
                "extra",
            ],
        ] {
            assert!(parse_command(args.into_iter().map(Into::into)).is_err());
        }

        let identity = Identity::new();
        let output = public_gateway_card(&identity).unwrap();
        let fields: Vec<_> = output.split(':').collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[..2], ["RSEG1", "sepolia"]);
        assert_eq!(hex::decode(fields[2]).unwrap().len(), 16);
        assert_eq!(
            fields[2],
            hex::encode(Destination::hash_from_name_and_identity(
                "lxmf.delivery",
                Some(&identity.hash)
            ))
        );
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(fields[3])
                .unwrap(),
            identity.get_public_key()
        );

        let contact = public_gateway_contact_card(&identity).unwrap();
        let contact_fields: Vec<_> = contact.strip_prefix("RSCP1:").unwrap().split(':').collect();
        assert_eq!(contact_fields.len(), 4);
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(contact_fields[0])
                .unwrap(),
            b"Ratspeak Sepolia Service"
        );
        assert_eq!(contact_fields[1], fields[2]);
        assert_eq!(contact_fields[2], hex::encode(identity.hash));
        assert_eq!(contact_fields[3], fields[3]);
    }

    #[test]
    fn public_card_query_is_load_only_and_available_while_service_lock_is_held() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity_path = temp.path().join("service.identity");
        assert!(load_service_identity(&identity_path).is_err());
        assert!(!identity_path.exists());

        let created = load_or_create_service_identity(&identity_path).unwrap();
        let _service_lock = InstanceLock::acquire(&temp.path().join("gateway.lock")).unwrap();
        let loaded = load_service_identity(&identity_path).unwrap();
        assert_eq!(loaded.hash, created.hash);
        assert!(
            public_gateway_card(&loaded)
                .unwrap()
                .starts_with("RSEG1:sepolia:")
        );
    }

    const RAW_NATIVE_TRANSFER: &str = "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725";

    struct AcceptedProvider;

    impl GatewayExecutionProvider for AcceptedProvider {
        fn submit_signed_relay(
            &mut self,
            relay: &AcceptedSignedRelay,
        ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
            Ok(RelayProviderObservation::new(
                relay.tx_hash(),
                RelayProviderStatus::Accepted,
            ))
        }

        fn observe_transaction_status(
            &mut self,
            _request: &ratspeak_eth_gateway::AcceptedTransactionStatusRequest,
        ) -> Result<ratspeak_eth_gateway::TransactionStatusObservation, GatewayProviderFailure>
        {
            Err(GatewayProviderFailure::Permanent)
        }

        fn fetch_verified_evidence(
            &mut self,
            _request: &AcceptedEvidenceRequest,
        ) -> Result<GatewayBundle, GatewayProviderFailure> {
            Err(GatewayProviderFailure::Permanent)
        }
    }

    struct Capture(Option<SealedOutboundLxmf>);

    impl OutboundLxmfTransport for Capture {
        fn send(
            &mut self,
            message: SealedOutboundLxmf,
        ) -> Result<TransportObservation, DaemonError> {
            self.0 = Some(message);
            Ok(TransportObservation::AcceptedForDelivery)
        }
    }

    fn relay_wire() -> Vec<u8> {
        let raw = hex::decode(RAW_NATIVE_TRANSFER).unwrap();
        let mut bytes = b"RSETHM1".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        bytes.push(4);
        bytes.extend_from_slice(&[0xA4; 16]);
        bytes.extend_from_slice(&10_000_u64.to_le_bytes());
        bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&raw);
        bytes
    }

    fn real_sealed_response() -> (SealedOutboundLxmf, [u8; 16], [u8; 16]) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let requester = Identity::new();
        let requester_destination =
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&requester.hash));
        let requester_private = requester.get_private_key().unwrap();
        let mut requester_seed = [0; 32];
        requester_seed.copy_from_slice(&requester_private[32..]);
        let requester_signing = Ed25519PrivateKey::from_bytes(&requester_seed);
        let node = Identity::new();
        let node_destination =
            Destination::hash_from_name_and_identity("lxmf.propagation", Some(&node.hash));
        let service = Identity::new();
        let config = GatewayDaemonConfig {
            rns_config_dir: temp.path().join("rns"),
            service_identity_path: temp.path().join("service.identity"),
            durable_gateway_db: temp.path().join("gateway.sqlite"),
            instance_lock_path: temp.path().join("gateway.lock"),
            requesters: vec![RequesterConfig {
                source_hash: hex::encode(requester_destination),
                ed25519_public_key: hex::encode(requester_signing.public_key().to_bytes()),
                rns_public_key: Some(hex::encode(requester.get_public_key())),
                contact_card_path: None,
            }],
            provider: ProviderConfig {
                checkpoint_root: hex::encode([0x44; 32]),
                checkpoint_epoch: 1,
                consensus_floor_path: temp.path().join("consensus.floor"),
                beacon_rpc_endpoint: "https://beacon.invalid".into(),
                execution_rpc_endpoint: "https://rpc.invalid".into(),
                beacon_authorization_path: None,
                execution_authorization_path: None,
                allow_loopback_http_for_development: false,
            },
            propagation: Some(PropagationConfig {
                node_destination_hash: hex::encode(node_destination),
                node_rns_public_key: hex::encode(node.get_public_key()),
                poll_interval_seconds: 60,
                delivery_limit_kb: 8,
                maximum_messages_per_poll: 1,
                outbound_fallback: true,
                node_transfer_limit_kb: 64,
                node_stamp_cost: 0,
            }),
            policy: DaemonPolicyConfig::default(),
        };
        let mut daemon = GatewayDaemon::open(&config, &service, AcceptedProvider).unwrap();
        let service_destination =
            Destination::hash_from_name_and_identity("lxmf.delivery", Some(&service.hash));
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
                &relay_wire(),
            )
            .unwrap();
        request.sign(&requester_signing).unwrap();
        let mut capture = Capture(None);
        daemon
            .handle_packed(
                &request.pack().unwrap(),
                InboundRoute::Direct,
                10,
                &mut capture,
            )
            .unwrap();
        (capture.0.unwrap(), requester_destination, node_destination)
    }

    struct RecordingExact {
        outcomes: VecDeque<Result<TransportObservation, DaemonError>>,
        destinations: Vec<[u8; 16]>,
    }

    impl ExactRnsSender for RecordingExact {
        fn send_exact(
            &mut self,
            message: SealedOutboundLxmf,
        ) -> Result<TransportObservation, DaemonError> {
            self.destinations.push(message.destination_hash());
            self.outcomes.pop_front().unwrap()
        }
    }

    #[test]
    fn real_direct_success_never_deposits_and_failure_attempts_exact_relay_second() {
        let (sealed, requester, node) = real_sealed_response();
        let mut direct_success = RnsOutbound {
            sender: RecordingExact {
                outcomes: VecDeque::from([Ok(TransportObservation::AcceptedForDelivery)]),
                destinations: Vec::new(),
            },
        };
        assert_eq!(
            direct_success.send(sealed.clone()),
            Ok(TransportObservation::AcceptedForDelivery)
        );
        assert_eq!(direct_success.sender.destinations, vec![requester]);

        let mut fallback = RnsOutbound {
            sender: RecordingExact {
                outcomes: VecDeque::from([
                    Err(DaemonError::TransportUnavailable),
                    Ok(TransportObservation::AcceptedForDelivery),
                ]),
                destinations: Vec::new(),
            },
        };
        assert_eq!(
            fallback.send(sealed),
            Ok(TransportObservation::AcceptedForDelivery)
        );
        assert_eq!(fallback.sender.destinations, vec![requester, node]);
    }

    #[test]
    fn scheduled_response_transport_failure_does_not_terminate_service() {
        assert_eq!(handle_scheduled_resume(Ok(1)), Ok(()));
        assert_eq!(
            handle_scheduled_resume(Err(DaemonError::TransportUnavailable)),
            Ok(())
        );
        assert_eq!(
            handle_scheduled_resume(Err(DaemonError::ServiceUnavailable)),
            Err(DaemonError::ServiceUnavailable)
        );
    }

    #[test]
    fn response_route_is_resolved_before_opening_a_link() {
        let source = include_str!("main.rs");
        let sender = &source[source
            .find("impl ExactRnsSender for RuntimeResourceSender")
            .unwrap()..];
        let route = sender.find(".await_path(").unwrap();
        let link = sender.find(".connect_link(").unwrap();
        assert!(route < link);
        assert!(sender[..link].contains("RESPONSE_ROUTE_DISCOVERY_TIMEOUT"));
    }

    #[test]
    fn direct_requests_reply_on_the_existing_authenticated_link() {
        let source = include_str!("main.rs");
        let event_loop = &source[source.find("loop {").unwrap()..];
        let link_packet = &event_loop[event_loop.find("link_packets.recv()").unwrap()..];
        let resource = &event_loop[event_loop.find("resource_completions.recv()").unwrap()..];
        assert!(
            link_packet[..link_packet.find("resource_completions.recv()").unwrap()]
                .contains("ExistingLinkOutbound")
        );
        assert!(resource.contains("link_id: resource.link_id"));
        assert!(source.contains("send_link_payload(link_id, payload, false)"));
    }
}
