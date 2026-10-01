//! Live consensus-to-execution evidence refresh.
//!
//! Each evidence request starts from the constructor-supplied checkpoint and
//! advances the stateful Beacon client. Execution JSON-RPC is then queried by
//! the exact Beacon-committed block hash. Neither provider can select a trust
//! root, and transport observations never become Ethereum confirmation.

use alloy_primitives::B256;
use alloy_rpc_types_eth::Header as RpcHeader;
use serde_json::json;
use std::time::{Duration, Instant};

use crate::provider::{
    canonical_data_hex, map_transport_failure, parse_field_fixed_hex, parse_field_quantity_u64,
    parse_fixed_hex, parse_quantity_u64, parse_rpc_result_bounded, prevalidate_relay,
};
use crate::{
    AcceptedEvidenceRequest, AcceptedSignedRelay, AcceptedTransactionStatusRequest,
    BeaconClientError, BeaconConsensusClient, BeaconHttpPolicy, BeaconHttpTransport,
    ExactReceiptProofBackend, GatewayBundle, GatewayExecutionProvider, GatewayHttpTransport,
    GatewayProviderFailure, ProviderHttpPolicy, RelayProviderObservation, RelayProviderStatus,
    SepoliaGatewayBuilder, TransactionPresence, TransactionStatusHead,
    TransactionStatusObservation, UnixClock, UntrustedExecutionAncestryRpcInput,
    UntrustedExecutionHeaderRpcInput,
};
use ratspeak_eth_verifier::{
    BeaconCheckpointRoot, MAX_ANCESTRY_HEADER_BYTES, MAX_ANCESTRY_HEADERS, MAX_BUNDLE_BYTES,
    SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, sepolia_slot_start_unix,
};

const HEADER_RPC_ID: u64 = 1;
// `eth_getBlockByHash(..., false)` omits full transaction objects but still
// returns the complete transaction-hash array. Keep the normal provider-wide
// JSON value ceiling here; a 256-value ceiling rejects ordinary blocks before
// the header can be hash-checked.
const MAX_HEADER_JSON_VALUES: usize = 8_192;
const MAX_STATUS_JSON_VALUES: usize = 64;
const MAX_ANCESTRY_FETCH_TIME: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LiveProviderError {
    #[error("live provider configuration was rejected")]
    Configuration,
}

/// Locally persisted state that prevents a restarted provider from accepting
/// older or conflicting consensus than it verified previously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedConsensusFloor {
    checkpoint_root: [u8; 32],
    finalized_slot: u64,
    execution_block_hash: [u8; 32],
}

impl VerifiedConsensusFloor {
    pub fn new(
        checkpoint_root: [u8; 32],
        finalized_slot: u64,
        execution_block_hash: [u8; 32],
    ) -> Result<Self, LiveProviderError> {
        if checkpoint_root == [0; 32] || finalized_slot == 0 || execution_block_hash == [0; 32] {
            return Err(LiveProviderError::Configuration);
        }
        Ok(Self {
            checkpoint_root,
            finalized_slot,
            execution_block_hash,
        })
    }

    pub fn checkpoint_root(self) -> [u8; 32] {
        self.checkpoint_root
    }

    pub fn finalized_slot(self) -> u64 {
        self.finalized_slot
    }

    pub fn execution_block_hash(self) -> [u8; 32] {
        self.execution_block_hash
    }
}

/// Daemon-owned persistence boundary for verified consensus monotonicity.
pub trait VerifiedConsensusFloorSink {
    /// Must durably commit `floor` before returning success.
    fn commit(&mut self, floor: VerifiedConsensusFloor) -> Result<(), GatewayProviderFailure>;
}

/// A provider which refreshes finalized consensus before every evidence cycle.
///
/// `checkpoint` is an operator-approved or independently cross-checked input;
/// no Beacon or execution response can replace it. Monotonicity is retained by
/// the owned `BeaconConsensusClient` for the lifetime of this process.
pub struct LiveSepoliaGatewayProvider<B, E, C, R> {
    checkpoint: BeaconCheckpointRoot,
    checkpoint_epoch: u64,
    beacon: BeaconConsensusClient<B, C>,
    execution: E,
    clock: C,
    receipt_backend: R,
    execution_policy: ProviderHttpPolicy,
    maximum_finalized_age: std::time::Duration,
    next_rpc_id: u64,
    consensus_floor_sink: Option<Box<dyn VerifiedConsensusFloorSink>>,
}

impl<B, E, C, R> std::fmt::Debug for LiveSepoliaGatewayProvider<B, E, C, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveSepoliaGatewayProvider")
            .field("beacon", &"checkpoint-pinned")
            .field("execution_policy", &self.execution_policy)
            .finish_non_exhaustive()
    }
}

impl<B, E, C, R> LiveSepoliaGatewayProvider<B, E, C, R>
where
    B: BeaconHttpTransport,
    C: UnixClock + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint: BeaconCheckpointRoot,
        checkpoint_epoch: u64,
        beacon_transport: B,
        execution_transport: E,
        clock: C,
        receipt_backend: R,
        beacon_policy: BeaconHttpPolicy,
        execution_policy: ProviderHttpPolicy,
    ) -> Result<Self, LiveProviderError> {
        if checkpoint_epoch == 0 {
            return Err(LiveProviderError::Configuration);
        }
        let beacon = BeaconConsensusClient::new(
            checkpoint.clone(),
            beacon_transport,
            clock.clone(),
            beacon_policy,
        )
        .map_err(|_| LiveProviderError::Configuration)?;
        // Validate through the existing constructor without retaining a dummy
        // builder or granting RPC authority.
        let execution_policy = execution_policy
            .validate()
            .map_err(|_| LiveProviderError::Configuration)?;
        Ok(Self {
            checkpoint,
            checkpoint_epoch,
            beacon,
            execution: execution_transport,
            clock,
            receipt_backend,
            execution_policy,
            maximum_finalized_age: beacon_policy.maximum_finalized_age,
            next_rpc_id: HEADER_RPC_ID,
            consensus_floor_sink: None,
        })
    }

    /// Installs a restart floor loaded from trusted local storage and a sink
    /// which will commit every newly verified floor before execution I/O.
    pub fn with_durable_consensus_floor(
        mut self,
        floor: Option<VerifiedConsensusFloor>,
        sink: Box<dyn VerifiedConsensusFloorSink>,
    ) -> Result<Self, LiveProviderError> {
        if let Some(floor) = floor {
            if floor.checkpoint_root != self.checkpoint.beacon_block_root() {
                return Err(LiveProviderError::Configuration);
            }
            self.beacon
                .restore_monotonic_floor(floor.finalized_slot, floor.execution_block_hash)
                .map_err(|_| LiveProviderError::Configuration)?;
        }
        self.consensus_floor_sink = Some(sink);
        Ok(self)
    }

    pub fn into_parts(self) -> (B, E, R) {
        (
            self.beacon.into_transport(),
            self.execution,
            self.receipt_backend,
        )
    }
}

impl<B, E, C, R> LiveSepoliaGatewayProvider<B, E, C, R>
where
    B: BeaconHttpTransport,
    E: GatewayHttpTransport,
    C: UnixClock + Clone,
{
    fn refresh_builder(&mut self) -> Result<SepoliaGatewayBuilder, GatewayProviderFailure> {
        let consensus = self.beacon.acquire_consensus().map_err(|error| {
            let reason = error;
            let failure = map_beacon_failure(error);
            tracing::warn!(
                stage = "beacon_consensus",
                class = ?failure,
                reason = ?reason,
                "Ethereum gateway provider request failed"
            );
            failure
        })?;
        let floor = VerifiedConsensusFloor::new(
            self.checkpoint.beacon_block_root(),
            consensus.finalized_slot(),
            consensus.execution_block_hash(),
        )
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        if let Some(sink) = &mut self.consensus_floor_sink {
            sink.commit(floor).inspect_err(|failure| {
                tracing::warn!(
                    stage = "consensus_floor_commit",
                    class = ?failure,
                    "Ethereum gateway provider request failed"
                );
            })?;
        }
        let hash = consensus.execution_block_hash();
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(HEADER_RPC_ID);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "eth_getBlockByHash",
            "params": [canonical_data_hex(&hash), false],
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .execution
            .post_json(
                &body,
                self.execution_policy.maximum_json_response_bytes,
                self.execution_policy.request_timeout,
            )
            .map_err(|error| {
                let failure = map_transport_failure(error);
                tracing::warn!(
                    stage = "execution_header_transport",
                    class = ?failure,
                    "Ethereum gateway provider request failed"
                );
                failure
            })?;
        if response.body().len() > self.execution_policy.maximum_json_response_bytes {
            tracing::warn!(
                stage = "execution_header_response_size",
                "Ethereum gateway provider request failed"
            );
            return Err(GatewayProviderFailure::Permanent);
        }
        let value = match response.status() {
            200..=299 => parse_rpc_result_bounded(response.body(), id, MAX_HEADER_JSON_VALUES)
                .inspect_err(|failure| {
                    tracing::warn!(stage = "execution_header_rpc_parse", class = ?failure, "Ethereum gateway provider request failed");
                })?,
            408 | 425 | 429 | 500..=599 => return Err(GatewayProviderFailure::Transient),
            status => {
                tracing::warn!(
                    stage = "execution_header_http_status",
                    status_class = status / 100,
                    "Ethereum gateway provider request failed"
                );
                return Err(GatewayProviderFailure::Permanent);
            }
        };
        if value.is_null() {
            return Err(GatewayProviderFailure::Transient);
        }
        let header: RpcHeader = serde_json::from_value(value).map_err(|_| {
            tracing::warn!(
                stage = "execution_header_decode",
                "Ethereum gateway provider request failed"
            );
            GatewayProviderFailure::Permanent
        })?;
        validate_header(&header, hash).inspect_err(|failure| {
            tracing::warn!(stage = "execution_header_validation", class = ?failure, "Ethereum gateway provider request failed");
        })?;
        let now_unix = self.clock.now_unix()?;
        // Recheck freshness after execution I/O; a slow or stalled RPC cannot
        // turn previously fresh consensus into acceptable old evidence.
        let finalized_at = sepolia_slot_start_unix(consensus.finalized_slot()).map_err(|_| {
            tracing::warn!(
                stage = "execution_header_finalized_time",
                "Ethereum gateway provider request failed"
            );
            GatewayProviderFailure::Permanent
        })?;
        let age = now_unix.checked_sub(finalized_at).ok_or_else(|| {
            tracing::warn!(
                stage = "execution_header_future",
                "Ethereum gateway provider request failed"
            );
            GatewayProviderFailure::Permanent
        })?;
        if age > self.maximum_finalized_age.as_secs() {
            tracing::warn!(
                stage = "execution_header_stale",
                age_seconds = age,
                maximum_age_seconds = self.maximum_finalized_age.as_secs(),
                "Ethereum gateway provider request failed"
            );
            return Err(GatewayProviderFailure::Permanent);
        }
        let execution = UntrustedExecutionHeaderRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: consensus.consensus_input().captured_at_unix,
            rlp_header: alloy_rlp::encode(&header.inner),
        };
        SepoliaGatewayBuilder::from_untrusted_rpc_at_unix(
            &self.checkpoint,
            consensus.consensus_input(),
            &execution,
            now_unix,
        )
        .map_err(|_| {
            tracing::warn!(
                stage = "execution_header_builder_verification",
                "Ethereum gateway provider request failed"
            );
            GatewayProviderFailure::Permanent
        })
    }

    fn execution_header_by_hash(
        &mut self,
        hash: [u8; 32],
        timeout: Duration,
    ) -> Result<RpcHeader, GatewayProviderFailure> {
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(HEADER_RPC_ID);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "eth_getBlockByHash",
            "params": [canonical_data_hex(&hash), false],
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .execution
            .post_json(
                &body,
                self.execution_policy.maximum_json_response_bytes,
                timeout,
            )
            .map_err(map_transport_failure)?;
        if response.body().len() > self.execution_policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        let value = match response.status() {
            200..=299 => parse_rpc_result_bounded(response.body(), id, MAX_HEADER_JSON_VALUES)?,
            408 | 425 | 429 | 500..=599 => return Err(GatewayProviderFailure::Transient),
            _ => return Err(GatewayProviderFailure::Permanent),
        };
        if value.is_null() {
            return Err(GatewayProviderFailure::Transient);
        }
        let header: RpcHeader =
            serde_json::from_value(value).map_err(|_| GatewayProviderFailure::Permanent)?;
        validate_header(&header, hash)?;
        Ok(header)
    }

    /// Calls only the four protocol-fixed status RPC methods. Its `method`
    /// argument is private and supplied solely by the two functions below;
    /// neither LXMF input nor an application caller can select a method/URL.
    fn transaction_status_rpc(
        &mut self,
        method: &'static str,
        params: serde_json::Value,
        maximum_json_values: usize,
    ) -> Result<serde_json::Value, GatewayProviderFailure> {
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(HEADER_RPC_ID);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .execution
            .post_json(
                &body,
                self.execution_policy.maximum_json_response_bytes,
                self.execution_policy.request_timeout,
            )
            .map_err(map_transport_failure)?;
        if response.body().len() > self.execution_policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        match response.status() {
            200..=299 => parse_rpc_result_bounded(response.body(), id, maximum_json_values),
            408 | 425 | 429 | 500..=599 => Err(GatewayProviderFailure::Transient),
            _ => Err(GatewayProviderFailure::Permanent),
        }
    }

    fn sampled_status_head(
        &mut self,
        tag: &'static str,
    ) -> Result<TransactionStatusHead, GatewayProviderFailure> {
        // Even with full transaction objects disabled, block responses carry
        // the complete transaction-hash array. Apply the same bounded header
        // ceiling used by ancestry/header acquisition.
        let value = self.transaction_status_rpc(
            "eth_getBlockByNumber",
            json!([tag, false]),
            MAX_HEADER_JSON_VALUES,
        )?;
        let object = value.as_object().ok_or(GatewayProviderFailure::Permanent)?;
        TransactionStatusHead::new(
            parse_field_quantity_u64(object, "number")?,
            parse_field_fixed_hex(object, "hash")?,
        )
        .map_err(|_| GatewayProviderFailure::Permanent)
    }

    fn sample_transaction_status(
        &mut self,
        tx_hash: [u8; 32],
    ) -> Result<TransactionStatusObservation, GatewayProviderFailure> {
        let transaction = self.transaction_status_rpc(
            "eth_getTransactionByHash",
            json!([canonical_data_hex(&tx_hash)]),
            MAX_STATUS_JSON_VALUES,
        )?;
        let (presence, included_number, included_hash) = if transaction.is_null() {
            (TransactionPresence::NotSeen, 0, [0; 32])
        } else {
            let object = transaction
                .as_object()
                .ok_or(GatewayProviderFailure::Permanent)?;
            if parse_field_fixed_hex(object, "hash")? != tx_hash {
                return Err(GatewayProviderFailure::Permanent);
            }
            match (object.get("blockNumber"), object.get("blockHash")) {
                (Some(serde_json::Value::Null), Some(serde_json::Value::Null)) => {
                    (TransactionPresence::Pending, 0, [0; 32])
                }
                (Some(number), Some(hash)) => (
                    TransactionPresence::Included,
                    parse_quantity_u64(number)?,
                    parse_fixed_hex(hash)?,
                ),
                _ => return Err(GatewayProviderFailure::Permanent),
            }
        };
        let latest = self.sampled_status_head("latest")?;
        let safe = self.sampled_status_head("safe")?;
        let finalized = self.sampled_status_head("finalized")?;
        TransactionStatusObservation::new(
            tx_hash,
            presence,
            included_number,
            included_hash,
            latest,
            safe,
            finalized,
        )
        .map_err(|_| GatewayProviderFailure::Permanent)
    }

    fn fetch_finalized_receipt(
        &mut self,
        request: &AcceptedEvidenceRequest,
        builder: &SepoliaGatewayBuilder,
        composite: bool,
    ) -> Result<GatewayBundle, GatewayProviderFailure>
    where
        R: ExactReceiptProofBackend,
    {
        let captured_at_unix = self.clock.now_unix()?;
        let location = self
            .receipt_backend
            .fetch_receipt_location(request.subject(), captured_at_unix)
            .inspect_err(|failure| {
                tracing::warn!(stage = "receipt_location", class = ?failure, "Ethereum gateway receipt refresh failed");
            })?;
        let ancestry_started = Instant::now();
        let rlp_headers = collect_execution_ancestry(
            builder.execution_block_number(),
            builder.execution_block_hash(),
            builder.execution_parent_hash(),
            location,
            |hash| {
                let remaining = MAX_ANCESTRY_FETCH_TIME
                    .checked_sub(ancestry_started.elapsed())
                    .ok_or(GatewayProviderFailure::Transient)?;
                self.execution_header_by_hash(
                    hash,
                    self.execution_policy.request_timeout.min(remaining),
                )
            },
        ).inspect_err(|failure| {
            tracing::warn!(stage = "receipt_ancestry", class = ?failure, "Ethereum gateway receipt refresh failed");
        })?;
        if ancestry_started.elapsed() >= MAX_ANCESTRY_FETCH_TIME {
            return Err(GatewayProviderFailure::Transient);
        }

        let mut receipt = self.receipt_backend.fetch_exact_receipt_proof(
            request.subject(),
            location.block_number,
            location.block_hash,
            captured_at_unix,
        ).inspect_err(|failure| {
            tracing::warn!(stage = "receipt_proof", class = ?failure, "Ethereum gateway receipt refresh failed");
        })?;
        receipt.captured_at_unix = captured_at_unix;
        if receipt.tx_hash != request.subject()
            || receipt.block_number != location.block_number
            || receipt.block_hash != location.block_hash
        {
            tracing::warn!(
                stage = "receipt_binding",
                "Ethereum gateway receipt refresh failed"
            );
            return Err(GatewayProviderFailure::Permanent);
        }
        let now_after_io = self.clock.now_unix()?;
        let finalized_at = sepolia_slot_start_unix(builder.finalized_slot())
            .map_err(|_| GatewayProviderFailure::Permanent)?;
        let age = now_after_io
            .checked_sub(finalized_at)
            .ok_or(GatewayProviderFailure::Permanent)?;
        if age > self.maximum_finalized_age.as_secs() {
            // A long proof reconstruction can outlive this anchor. A later
            // attempt must acquire a fresh finalized head rather than
            // permanently completing the still-valid transaction request.
            return Err(GatewayProviderFailure::Transient);
        }
        let ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: location.block_number,
            target_block_hash: location.block_hash,
            rlp_headers,
        };
        let bundle = if composite {
            builder.build_finalized_receipt_evidence(&ancestry, &receipt)
        } else {
            builder.build_finalized_tx_receipt_proof(&ancestry, &receipt)
        };
        bundle.map_err(|_| {
            tracing::warn!(
                stage = "receipt_bundle",
                "Ethereum gateway receipt refresh failed"
            );
            GatewayProviderFailure::Permanent
        })
    }
}

fn collect_execution_ancestry(
    anchor_number: u64,
    anchor_hash: [u8; 32],
    anchor_parent_hash: [u8; 32],
    location: crate::UntrustedReceiptLocation,
    mut fetch: impl FnMut([u8; 32]) -> Result<RpcHeader, GatewayProviderFailure>,
) -> Result<Vec<Vec<u8>>, GatewayProviderFailure> {
    let distance = anchor_number
        .checked_sub(location.block_number)
        .ok_or(GatewayProviderFailure::Transient)?;
    let distance = usize::try_from(distance).map_err(|_| GatewayProviderFailure::Permanent)?;
    if distance > MAX_ANCESTRY_HEADERS {
        return Err(GatewayProviderFailure::Permanent);
    }
    if distance == 0 {
        return if location.block_hash == anchor_hash {
            Ok(Vec::new())
        } else {
            // The location hint and finalized head were sampled separately.
            // A reorg or lagging backend can make them disagree temporarily.
            Err(GatewayProviderFailure::Transient)
        };
    }

    let mut rlp_headers = Vec::with_capacity(distance);
    let mut expected_hash = anchor_parent_hash;
    let mut expected_number = anchor_number;
    let mut observed_target = None;
    let mut encoded_total = 0_usize;
    for _ in 0..distance {
        expected_number = expected_number
            .checked_sub(1)
            .ok_or(GatewayProviderFailure::Permanent)?;
        let header = fetch(expected_hash)?;
        if header.hash.0 != expected_hash
            || header.inner.hash_slow().0 != expected_hash
            || header.inner.number != expected_number
        {
            return Err(GatewayProviderFailure::Permanent);
        }
        observed_target = Some((expected_hash, header.inner.number));
        expected_hash = header.inner.parent_hash.0;
        let encoded = alloy_rlp::encode(&header.inner);
        encoded_total = encoded_total
            .checked_add(encoded.len())
            .filter(|total| *total <= MAX_BUNDLE_BYTES)
            .ok_or(GatewayProviderFailure::Permanent)?;
        if encoded.is_empty() || encoded.len() > MAX_ANCESTRY_HEADER_BYTES {
            return Err(GatewayProviderFailure::Permanent);
        }
        rlp_headers.push(encoded);
    }
    if observed_target != Some((location.block_hash, location.block_number)) {
        // The hinted location is not on this finalized ancestry. Retry from a
        // newly acquired consensus head; do not turn a reorg race into a
        // durable terminal result.
        return Err(GatewayProviderFailure::Transient);
    }
    Ok(rlp_headers)
}

impl<B, E, C, R> GatewayExecutionProvider for LiveSepoliaGatewayProvider<B, E, C, R>
where
    B: BeaconHttpTransport,
    E: GatewayHttpTransport,
    C: UnixClock + Clone,
    R: ExactReceiptProofBackend,
{
    fn submit_signed_relay(
        &mut self,
        relay: &AcceptedSignedRelay,
    ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
        prevalidate_relay(relay)?;
        let id = self.next_rpc_id;
        self.next_rpc_id = self.next_rpc_id.checked_add(1).unwrap_or(HEADER_RPC_ID);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "eth_sendRawTransaction",
            "params": [canonical_data_hex(relay.raw_transaction())],
        }))
        .map_err(|_| GatewayProviderFailure::Permanent)?;
        let response = self
            .execution
            .post_json(
                &body,
                self.execution_policy.maximum_json_response_bytes,
                self.execution_policy.request_timeout,
            )
            .map_err(map_transport_failure)?;
        if response.body().len() > self.execution_policy.maximum_json_response_bytes {
            return Err(GatewayProviderFailure::Permanent);
        }
        let value = match response.status() {
            200..=299 => parse_rpc_result_bounded(response.body(), id, MAX_HEADER_JSON_VALUES)?,
            408 | 425 | 429 | 500..=599 => return Err(GatewayProviderFailure::Transient),
            _ => return Err(GatewayProviderFailure::Permanent),
        };
        if value.as_str() != Some(&canonical_data_hex(&relay.tx_hash())) {
            return Err(GatewayProviderFailure::Permanent);
        }
        Ok(RelayProviderObservation::new(
            relay.tx_hash(),
            RelayProviderStatus::Accepted,
        ))
    }

    fn observe_transaction_status(
        &mut self,
        request: &AcceptedTransactionStatusRequest,
    ) -> Result<TransactionStatusObservation, GatewayProviderFailure> {
        self.sample_transaction_status(request.tx_hash())
    }

    fn fetch_verified_evidence(
        &mut self,
        request: &AcceptedEvidenceRequest,
    ) -> Result<GatewayBundle, GatewayProviderFailure> {
        let composite = matches!(
            request.evidence_kind(),
            crate::MessagingEvidenceKind::AccountStatePackage
                | crate::MessagingEvidenceKind::FinalizedReceiptPackage
        );
        if composite {
            let Some(context) = request.checkpoint_context() else {
                return Err(GatewayProviderFailure::Permanent);
            };
            if context.epoch() != self.checkpoint_epoch
                || context.root() != self.checkpoint.beacon_block_root()
            {
                // Reject before Beacon, execution, or receipt I/O. Incoming
                // bytes cannot select the daemon's trust anchor.
                tracing::warn!(
                    stage = "checkpoint_context",
                    class = ?GatewayProviderFailure::Permanent,
                    "Ethereum gateway provider request failed"
                );
                return Err(GatewayProviderFailure::Permanent);
            }
        }
        let builder = self.refresh_builder().inspect_err(|failure| {
            tracing::warn!(
                stage = "verified_header_refresh",
                class = ?failure,
                "Ethereum gateway provider request failed"
            );
        })?;
        if matches!(
            request.evidence_kind(),
            crate::MessagingEvidenceKind::ReceiptProof
                | crate::MessagingEvidenceKind::FinalizedReceiptPackage
        ) {
            return self.fetch_finalized_receipt(request, &builder, composite);
        }
        let mut provider = crate::SepoliaRpcProvider::new(
            builder,
            BorrowedTransport(&mut self.execution),
            self.clock.clone(),
            self.execution_policy,
        )
        .map_err(|_| GatewayProviderFailure::Permanent)?
        .with_receipt_backend(BorrowedReceiptBackend(&mut self.receipt_backend));
        provider
            .fetch_verified_evidence(request)
            .inspect_err(|failure| {
                tracing::warn!(
                    stage = "account_or_execution_proof",
                    class = ?failure,
                    "Ethereum gateway provider request failed"
                );
            })
    }
}

struct BorrowedTransport<'a, T>(&'a mut T);

impl<T: GatewayHttpTransport> GatewayHttpTransport for BorrowedTransport<'_, T> {
    fn post_json(
        &mut self,
        body: &[u8],
        maximum_response_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<crate::GatewayHttpResponse, crate::HttpTransportFailure> {
        self.0.post_json(body, maximum_response_bytes, timeout)
    }
}

struct BorrowedReceiptBackend<'a, R>(&'a mut R);

impl<R: ExactReceiptProofBackend> ExactReceiptProofBackend for BorrowedReceiptBackend<'_, R> {
    fn fetch_receipt_location(
        &mut self,
        tx_hash: [u8; 32],
        captured_at_unix: u64,
    ) -> Result<crate::UntrustedReceiptLocation, GatewayProviderFailure> {
        self.0.fetch_receipt_location(tx_hash, captured_at_unix)
    }

    fn fetch_exact_receipt_proof(
        &mut self,
        tx_hash: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        captured_at_unix: u64,
    ) -> Result<crate::UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
        self.0.fetch_exact_receipt_proof(
            tx_hash,
            execution_block_number,
            execution_block_hash,
            captured_at_unix,
        )
    }
}

fn validate_header(
    header: &RpcHeader,
    expected_hash: [u8; 32],
) -> Result<(), GatewayProviderFailure> {
    let expected = B256::from(expected_hash);
    if header.hash != expected || header.inner.hash_slow() != expected {
        return Err(GatewayProviderFailure::Permanent);
    }
    Ok(())
}

fn map_beacon_failure(error: BeaconClientError) -> GatewayProviderFailure {
    match error {
        BeaconClientError::Transient | BeaconClientError::AcquisitionLimit => {
            GatewayProviderFailure::Transient
        }
        _ => GatewayProviderFailure::Permanent,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::messaging::{
        AuthenticatedGatewayEnvelope, GatewayMessageOutcome, GatewayRateLimit, GatewayRelayGuard,
        MessagingEvidenceKind, encode_test_contextual_evidence_request,
    };
    use alloy_consensus::Header;
    use base64::Engine;

    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];
    const CAPTURED_AT_UNIX: u64 = 1_788_034_160;
    const FINALIZED_SLOT: u64 = 11_024_959;

    struct UnusedBeacon;

    impl BeaconHttpTransport for UnusedBeacon {
        fn get_ssz(
            &mut self,
            _path_and_query: &str,
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::BeaconHttpResponse, crate::HttpTransportFailure> {
            Err(crate::HttpTransportFailure::Transient)
        }
    }

    struct PanicBeacon;

    impl BeaconHttpTransport for PanicBeacon {
        fn get_ssz(
            &mut self,
            _path_and_query: &str,
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::BeaconHttpResponse, crate::HttpTransportFailure> {
            panic!("checkpoint mismatch must precede Beacon I/O")
        }
    }

    struct ScriptedBeacon {
        replies: VecDeque<crate::BeaconHttpResponse>,
    }

    impl ScriptedBeacon {
        fn successful() -> Self {
            fn decode(value: &str) -> Vec<u8> {
                let compact: String = value
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                base64::engine::general_purpose::STANDARD
                    .decode(compact)
                    .unwrap()
            }
            let bootstrap = decode(include_str!(
                "../../ratspeak-eth-verifier/tests/fixtures/sepolia-bootstrap-343888.ssz.b64"
            ));
            let finality = decode(include_str!(
                "../tests/fixtures/sepolia-finality-2026-08-29.ssz.b64"
            ));
            Self {
                replies: VecDeque::from([
                    crate::BeaconHttpResponse::new(
                        200,
                        Some("application/octet-stream"),
                        Some("fulu"),
                        None,
                        bootstrap,
                    ),
                    crate::BeaconHttpResponse::new(
                        200,
                        Some("application/octet-stream"),
                        None,
                        None,
                        include_bytes!("../tests/fixtures/sepolia-updates-1343-1344.ssz").to_vec(),
                    ),
                    crate::BeaconHttpResponse::new(
                        200,
                        Some("application/octet-stream"),
                        None,
                        None,
                        include_bytes!("../tests/fixtures/sepolia-update-1345.ssz").to_vec(),
                    ),
                    crate::BeaconHttpResponse::new(
                        200,
                        Some("application/octet-stream"),
                        Some("fulu"),
                        None,
                        finality,
                    ),
                ]),
            }
        }
    }

    impl BeaconHttpTransport for ScriptedBeacon {
        fn get_ssz(
            &mut self,
            _path_and_query: &str,
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::BeaconHttpResponse, crate::HttpTransportFailure> {
            self.replies
                .pop_front()
                .ok_or(crate::HttpTransportFailure::Permanent)
        }
    }

    #[derive(Default)]
    struct UnusedExecution {
        calls: usize,
    }

    struct HeaderExecution {
        response: Option<crate::GatewayHttpResponse>,
    }

    impl GatewayHttpTransport for HeaderExecution {
        fn post_json(
            &mut self,
            _body: &[u8],
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::GatewayHttpResponse, crate::HttpTransportFailure> {
            self.response
                .take()
                .ok_or(crate::HttpTransportFailure::Permanent)
        }
    }

    struct StatusExecution {
        replies: VecDeque<Result<crate::GatewayHttpResponse, crate::HttpTransportFailure>>,
        methods: Vec<String>,
    }

    impl StatusExecution {
        fn from_results(results: impl IntoIterator<Item = serde_json::Value>) -> Self {
            Self {
                replies: results
                    .into_iter()
                    .enumerate()
                    .map(|(index, result)| {
                        Ok(crate::GatewayHttpResponse::new(
                            200,
                            serde_json::to_vec(
                                &json!({"jsonrpc":"2.0","id": index as u64 + 1,"result":result}),
                            )
                            .unwrap(),
                        ))
                    })
                    .collect(),
                methods: Vec::new(),
            }
        }
    }

    impl GatewayHttpTransport for StatusExecution {
        fn post_json(
            &mut self,
            body: &[u8],
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::GatewayHttpResponse, crate::HttpTransportFailure> {
            let request: serde_json::Value = serde_json::from_slice(body).unwrap();
            self.methods
                .push(request["method"].as_str().unwrap().to_owned());
            self.replies
                .pop_front()
                .unwrap_or(Err(crate::HttpTransportFailure::Permanent))
        }
    }

    impl GatewayHttpTransport for UnusedExecution {
        fn post_json(
            &mut self,
            _body: &[u8],
            _maximum_response_bytes: usize,
            _timeout: std::time::Duration,
        ) -> Result<crate::GatewayHttpResponse, crate::HttpTransportFailure> {
            self.calls += 1;
            Err(crate::HttpTransportFailure::Transient)
        }
    }

    #[derive(Clone)]
    struct FixedClock(u64);

    impl UnixClock for FixedClock {
        fn now_unix(&self) -> Result<u64, GatewayProviderFailure> {
            Ok(self.0)
        }
    }

    struct UnusedReceipts;

    impl ExactReceiptProofBackend for UnusedReceipts {
        fn fetch_exact_receipt_proof(
            &mut self,
            _tx_hash: [u8; 32],
            _execution_block_number: u64,
            _execution_block_hash: [u8; 32],
            _captured_at_unix: u64,
        ) -> Result<crate::UntrustedTxReceiptProofRpcInput, GatewayProviderFailure> {
            Err(GatewayProviderFailure::Transient)
        }
    }

    struct UnusedFloorSink;

    impl VerifiedConsensusFloorSink for UnusedFloorSink {
        fn commit(&mut self, _floor: VerifiedConsensusFloor) -> Result<(), GatewayProviderFailure> {
            Ok(())
        }
    }

    struct FailingFloorSink;

    impl VerifiedConsensusFloorSink for FailingFloorSink {
        fn commit(&mut self, _floor: VerifiedConsensusFloor) -> Result<(), GatewayProviderFailure> {
            Err(GatewayProviderFailure::Permanent)
        }
    }

    #[test]
    fn canonical_rpc_header_must_match_both_claimed_and_recomputed_hash() {
        let inner = Header::default();
        let hash = inner.hash_slow();
        let rpc = RpcHeader {
            hash,
            inner,
            ..Default::default()
        };
        validate_header(&rpc, hash.0).unwrap();

        let mut wrong_claim = rpc.clone();
        wrong_claim.hash = B256::repeat_byte(0x55);
        assert_eq!(
            validate_header(&wrong_claim, hash.0),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            validate_header(&rpc, [0x44; 32]),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn ancestry_header_allows_bounded_transaction_hash_arrays() {
        let inner = Header::default();
        let hash = inner.hash_slow();
        let mut result = serde_json::to_value(RpcHeader {
            hash,
            inner,
            ..Default::default()
        })
        .unwrap();
        result.as_object_mut().unwrap().insert(
            "transactions".to_owned(),
            serde_json::Value::Array(
                (0..300)
                    .map(|_| serde_json::Value::String("0x00".to_owned()))
                    .collect(),
            ),
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        }))
        .unwrap();
        let mut provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            UnusedBeacon,
            HeaderExecution {
                response: Some(crate::GatewayHttpResponse::new(200, body)),
            },
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            BeaconHttpPolicy::conservative(),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        provider
            .execution_header_by_hash(hash.0, Duration::from_secs(1))
            .unwrap();

        let mut oversized = serde_json::to_value(RpcHeader {
            hash,
            inner: Header::default(),
            ..Default::default()
        })
        .unwrap();
        oversized.as_object_mut().unwrap().insert(
            "transactions".to_owned(),
            serde_json::Value::Array(
                (0..8_193)
                    .map(|_| serde_json::Value::String("0x00".to_owned()))
                    .collect(),
            ),
        );
        let oversized_body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": oversized,
        }))
        .unwrap();
        let mut oversized_provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            UnusedBeacon,
            HeaderExecution {
                response: Some(crate::GatewayHttpResponse::new(200, oversized_body)),
            },
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            BeaconHttpPolicy::conservative(),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            oversized_provider.execution_header_by_hash(hash.0, Duration::from_secs(1)),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    fn status_head(number: u64, byte: u8) -> serde_json::Value {
        serde_json::json!({
            "number": format!("0x{number:x}"),
            "hash": crate::provider::canonical_data_hex(&[byte; 32]),
        })
    }

    fn status_provider(
        execution: StatusExecution,
    ) -> LiveSepoliaGatewayProvider<UnusedBeacon, StatusExecution, FixedClock, UnusedReceipts> {
        LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            UnusedBeacon,
            execution,
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            BeaconHttpPolicy::conservative(),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap()
    }

    #[test]
    fn transaction_status_uses_only_fixed_rpc_methods_and_exact_shapes() {
        let tx_hash = [0x81; 32];
        let transaction = serde_json::json!({
            "hash": crate::provider::canonical_data_hex(&tx_hash),
            "blockNumber": "0x64",
            "blockHash": crate::provider::canonical_data_hex(&[0x82; 32]),
        });
        let execution = StatusExecution::from_results([
            transaction,
            status_head(105, 0x83),
            status_head(104, 0x84),
            status_head(103, 0x85),
        ]);
        let mut provider = status_provider(execution);
        let observation = provider.sample_transaction_status(tx_hash).unwrap();
        assert_eq!(observation.presence(), TransactionPresence::Included);
        assert_eq!(observation.included_block_number(), 100);
        assert_eq!(observation.included_block_hash(), [0x82; 32]);
        assert_eq!(observation.latest().number(), 105);
        assert_eq!(
            provider.execution.methods,
            [
                "eth_getTransactionByHash",
                "eth_getBlockByNumber",
                "eth_getBlockByNumber",
                "eth_getBlockByNumber",
            ]
        );
    }

    #[test]
    fn transaction_status_heads_allow_bounded_transaction_hash_arrays() {
        let tx_hash = [0x86; 32];
        let transaction = serde_json::json!({
            "hash": crate::provider::canonical_data_hex(&tx_hash),
            "blockNumber": "0x64",
            "blockHash": crate::provider::canonical_data_hex(&[0x87; 32]),
        });
        let head_with_transactions = |number, byte| {
            let mut head = status_head(number, byte);
            head.as_object_mut().unwrap().insert(
                "transactions".to_owned(),
                serde_json::Value::Array(
                    (0..300)
                        .map(|_| serde_json::Value::String("0x00".to_owned()))
                        .collect(),
                ),
            );
            head
        };
        let execution = StatusExecution::from_results([
            transaction,
            head_with_transactions(105, 0x88),
            head_with_transactions(104, 0x89),
            head_with_transactions(103, 0x8a),
        ]);
        let observation = status_provider(execution)
            .sample_transaction_status(tx_hash)
            .unwrap();
        assert_eq!(observation.presence(), TransactionPresence::Included);
        assert_eq!(observation.latest().number(), 105);
        assert_eq!(observation.finalized().number(), 103);
    }

    #[test]
    fn transaction_status_not_seen_pending_and_malformed_shapes_are_fail_closed() {
        let tx_hash = [0x91; 32];
        for (transaction, expected) in [
            (serde_json::Value::Null, Some(TransactionPresence::NotSeen)),
            (
                serde_json::json!({
                    "hash": crate::provider::canonical_data_hex(&tx_hash),
                    "blockNumber": null,
                    "blockHash": null,
                }),
                Some(TransactionPresence::Pending),
            ),
            (
                serde_json::json!({
                    "hash": crate::provider::canonical_data_hex(&tx_hash),
                    "blockNumber": "0x64",
                    "blockHash": null,
                }),
                None,
            ),
        ] {
            let execution = StatusExecution::from_results([
                transaction,
                status_head(105, 0x93),
                status_head(104, 0x94),
                status_head(103, 0x95),
            ]);
            let mut provider = status_provider(execution);
            let result = provider.sample_transaction_status(tx_hash);
            match expected {
                Some(presence) => assert_eq!(result.unwrap().presence(), presence),
                None => assert_eq!(result, Err(GatewayProviderFailure::Permanent)),
            }
        }

        let wrong_hash = StatusExecution::from_results([serde_json::json!({
            "hash": crate::provider::canonical_data_hex(&[0x99; 32]),
            "blockNumber": null,
            "blockHash": null,
        })]);
        assert_eq!(
            status_provider(wrong_hash).sample_transaction_status(tx_hash),
            Err(GatewayProviderFailure::Permanent)
        );

        let zero_head = StatusExecution::from_results([
            serde_json::Value::Null,
            serde_json::json!({"number":"0x0", "hash": crate::provider::canonical_data_hex(&[1; 32])}),
        ]);
        assert_eq!(
            status_provider(zero_head).sample_transaction_status(tx_hash),
            Err(GatewayProviderFailure::Permanent)
        );
    }

    #[test]
    fn transaction_status_http_and_response_failures_are_bounded() {
        let tx_hash = [0xa1; 32];
        let transient = StatusExecution {
            replies: VecDeque::from([Ok(crate::GatewayHttpResponse::new(503, Vec::new()))]),
            methods: Vec::new(),
        };
        assert_eq!(
            status_provider(transient).sample_transaction_status(tx_hash),
            Err(GatewayProviderFailure::Transient)
        );
        let malformed = StatusExecution {
            replies: VecDeque::from([Ok(crate::GatewayHttpResponse::new(
                200,
                b"not json".to_vec(),
            ))]),
            methods: Vec::new(),
        };
        assert_eq!(
            status_provider(malformed).sample_transaction_status(tx_hash),
            Err(GatewayProviderFailure::Transient)
        );
    }

    fn rpc_header(inner: Header) -> RpcHeader {
        RpcHeader {
            hash: inner.hash_slow(),
            inner,
            ..Default::default()
        }
    }

    #[test]
    fn ancestry_walk_uses_exact_parent_hashes_and_adjacent_numbers() {
        let target = rpc_header(Header {
            number: 10,
            parent_hash: [0x09; 32].into(),
            ..Default::default()
        });
        let intermediate = rpc_header(Header {
            number: 11,
            parent_hash: target.hash,
            ..Default::default()
        });
        let mut replies = VecDeque::from([intermediate.clone(), target.clone()]);
        let headers = collect_execution_ancestry(
            12,
            [0x12; 32],
            intermediate.hash.0,
            crate::UntrustedReceiptLocation {
                block_number: 10,
                block_hash: target.hash.0,
            },
            |expected| {
                let header = replies
                    .pop_front()
                    .ok_or(GatewayProviderFailure::Transient)?;
                assert_eq!(header.hash.0, expected);
                Ok(header)
            },
        )
        .unwrap();
        assert_eq!(headers.len(), 2);
        assert!(replies.is_empty());

        let wrong_order = collect_execution_ancestry(
            12,
            [0x12; 32],
            intermediate.hash.0,
            crate::UntrustedReceiptLocation {
                block_number: 10,
                block_hash: target.hash.0,
            },
            |_| Ok(target.clone()),
        );
        assert_eq!(wrong_order, Err(GatewayProviderFailure::Permanent));

        let same_height = rpc_header(Header {
            number: 12,
            parent_hash: target.hash,
            ..Default::default()
        });
        assert_eq!(
            collect_execution_ancestry(
                12,
                [0x12; 32],
                same_height.hash.0,
                crate::UntrustedReceiptLocation {
                    block_number: 11,
                    block_hash: same_height.hash.0,
                },
                |_| Ok(same_height.clone()),
            ),
            Err(GatewayProviderFailure::Permanent)
        );

        let parent_hash = intermediate.hash.0;
        let mut canonical = VecDeque::from([intermediate, target]);
        assert_eq!(
            collect_execution_ancestry(
                12,
                [0x12; 32],
                parent_hash,
                crate::UntrustedReceiptLocation {
                    block_number: 10,
                    block_hash: [0x99; 32],
                },
                |_| canonical
                    .pop_front()
                    .ok_or(GatewayProviderFailure::Transient),
            ),
            Err(GatewayProviderFailure::Transient)
        );
    }

    #[test]
    fn ancestry_walk_refuses_unfinalized_too_old_forked_and_missing_targets() {
        let never = |_| -> Result<RpcHeader, GatewayProviderFailure> {
            panic!("invalid location must fail before execution I/O")
        };
        assert_eq!(
            collect_execution_ancestry(
                12,
                [0x12; 32],
                [0x11; 32],
                crate::UntrustedReceiptLocation {
                    block_number: 13,
                    block_hash: [0x13; 32],
                },
                never,
            ),
            Err(GatewayProviderFailure::Transient)
        );
        assert_eq!(
            collect_execution_ancestry(
                300,
                [0x30; 32],
                [0x29; 32],
                crate::UntrustedReceiptLocation {
                    block_number: 43,
                    block_hash: [0x43; 32],
                },
                never,
            ),
            Err(GatewayProviderFailure::Permanent)
        );
        assert_eq!(
            collect_execution_ancestry(
                12,
                [0x12; 32],
                [0x11; 32],
                crate::UntrustedReceiptLocation {
                    block_number: 12,
                    block_hash: [0x99; 32],
                },
                never,
            ),
            Err(GatewayProviderFailure::Transient)
        );
        assert_eq!(
            collect_execution_ancestry(
                12,
                [0x12; 32],
                [0x11; 32],
                crate::UntrustedReceiptLocation {
                    block_number: 11,
                    block_hash: [0x11; 32],
                },
                |_| Err(GatewayProviderFailure::Transient),
            ),
            Err(GatewayProviderFailure::Transient)
        );
    }

    #[test]
    fn only_retryable_beacon_failures_remain_retryable() {
        assert_eq!(
            map_beacon_failure(BeaconClientError::Transient),
            GatewayProviderFailure::Transient
        );
        assert_eq!(
            map_beacon_failure(BeaconClientError::AcquisitionLimit),
            GatewayProviderFailure::Transient
        );
        for error in [
            BeaconClientError::Rollback,
            BeaconClientError::Conflict,
            BeaconClientError::ClockPolicy,
            BeaconClientError::VerificationFailed,
            BeaconClientError::ExecutionMismatch,
        ] {
            assert_eq!(map_beacon_failure(error), GatewayProviderFailure::Permanent);
        }
    }

    #[test]
    fn durable_floor_must_belong_to_constructor_checkpoint() {
        let checkpoint_root = [0x44; 32];
        let provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(checkpoint_root),
            1,
            UnusedBeacon,
            UnusedExecution::default(),
            FixedClock(1_800_000_000),
            UnusedReceipts,
            BeaconHttpPolicy::conservative(),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        let wrong = VerifiedConsensusFloor::new([0x45; 32], 1, [0x55; 32]).unwrap();
        assert!(matches!(
            provider.with_durable_consensus_floor(Some(wrong), Box::new(UnusedFloorSink)),
            Err(LiveProviderError::Configuration)
        ));
    }

    #[test]
    fn contextual_request_mismatch_precedes_all_provider_io() {
        const REQUESTER: [u8; 16] = [0x31; 16];
        let wire = encode_test_contextual_evidence_request(
            [0x41; 16],
            MessagingEvidenceKind::AccountStatePackage,
            [0x11; 32],
            343_888,
            [0x55; 32],
            ratspeak_eth_verifier::MAX_BUNDLE_BYTES as u32,
            true,
            CAPTURED_AT_UNIX + 1_000,
        );
        let mut guard =
            GatewayRelayGuard::new(REQUESTER, GatewayRateLimit::conservative()).unwrap();
        let GatewayMessageOutcome::EvidenceRequest(request) = guard
            .handle_persisted_attachment(
                AuthenticatedGatewayEnvelope::from_verified_lxmf(REQUESTER, &wire),
                CAPTURED_AT_UNIX,
            )
            .unwrap()
        else {
            panic!("expected evidence request")
        };
        let mut provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            343_888,
            PanicBeacon,
            UnusedExecution::default(),
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            BeaconHttpPolicy::conservative(),
            ProviderHttpPolicy::conservative(),
        )
        .unwrap();
        assert_eq!(
            provider.fetch_verified_evidence(&request),
            Err(GatewayProviderFailure::Permanent)
        );
        let (_, execution, _) = provider.into_parts();
        assert_eq!(execution.calls, 0);
    }

    #[test]
    fn consensus_floor_rejects_empty_security_fields() {
        assert_eq!(
            VerifiedConsensusFloor::new([0; 32], 1, [0x55; 32]),
            Err(LiveProviderError::Configuration)
        );
        assert_eq!(
            VerifiedConsensusFloor::new([0x44; 32], 0, [0x55; 32]),
            Err(LiveProviderError::Configuration)
        );
        assert_eq!(
            VerifiedConsensusFloor::new([0x44; 32], 1, [0; 32]),
            Err(LiveProviderError::Configuration)
        );
    }

    #[test]
    fn durable_floor_failure_precedes_all_execution_io() {
        let mut beacon_policy = BeaconHttpPolicy::conservative();
        beacon_policy.maximum_finalized_age = std::time::Duration::from_secs(20 * 60);
        let mut provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            ScriptedBeacon::successful(),
            UnusedExecution::default(),
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            beacon_policy,
            ProviderHttpPolicy::conservative(),
        )
        .unwrap()
        .with_durable_consensus_floor(None, Box::new(FailingFloorSink))
        .unwrap();
        assert!(matches!(
            provider.refresh_builder(),
            Err(GatewayProviderFailure::Permanent)
        ));
        let (_, execution, _) = provider.into_parts();
        assert_eq!(execution.calls, 0);
    }

    #[test]
    fn restored_floor_rejects_rollback_before_execution_io() {
        let mut beacon_policy = BeaconHttpPolicy::conservative();
        beacon_policy.maximum_finalized_age = std::time::Duration::from_secs(20 * 60);
        let floor =
            VerifiedConsensusFloor::new(CHECKPOINT_ROOT, FINALIZED_SLOT + 1, [0x77; 32]).unwrap();
        let mut provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            ScriptedBeacon::successful(),
            UnusedExecution::default(),
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            beacon_policy,
            ProviderHttpPolicy::conservative(),
        )
        .unwrap()
        .with_durable_consensus_floor(Some(floor), Box::new(UnusedFloorSink))
        .unwrap();
        assert!(matches!(
            provider.refresh_builder(),
            Err(GatewayProviderFailure::Permanent)
        ));
        let (_, execution, _) = provider.into_parts();
        assert_eq!(execution.calls, 0);
    }

    #[test]
    fn restored_floor_rejects_same_slot_conflict_before_execution_io() {
        let mut beacon_policy = BeaconHttpPolicy::conservative();
        beacon_policy.maximum_finalized_age = std::time::Duration::from_secs(20 * 60);
        let floor =
            VerifiedConsensusFloor::new(CHECKPOINT_ROOT, FINALIZED_SLOT, [0x77; 32]).unwrap();
        let mut provider = LiveSepoliaGatewayProvider::new(
            BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            1,
            ScriptedBeacon::successful(),
            UnusedExecution::default(),
            FixedClock(CAPTURED_AT_UNIX),
            UnusedReceipts,
            beacon_policy,
            ProviderHttpPolicy::conservative(),
        )
        .unwrap()
        .with_durable_consensus_floor(Some(floor), Box::new(UnusedFloorSink))
        .unwrap();
        assert!(matches!(
            provider.refresh_builder(),
            Err(GatewayProviderFailure::Permanent)
        ));
        let (_, execution, _) = provider.into_parts();
        assert_eq!(execution.calls, 0);
    }
}
