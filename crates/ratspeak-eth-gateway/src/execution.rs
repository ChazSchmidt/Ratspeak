//! Restart-safe execution of work admitted at the authenticated gateway edge.
//!
//! Provider implementations are deliberately injected. This crate has no
//! endpoint, credential, peer-discovery, or transport configuration surface.
//! RPC relay observations remain non-authoritative, and evidence can leave the
//! executor only as a gateway bundle already accepted by the local verifier.

use crate::{
    AcceptedEvidenceRequest, AcceptedSignedRelay, AcceptedTransactionStatusRequest,
    DurableGatewayAdmission, GatewayAdmissionError, GatewayBundle, GatewayMessageError,
    GatewayMessageOutcome, GatewayRateLimit, GatewayRelayGuard, GatewayResultKind,
    GatewayStoredResult, RelayObservation, TransactionStatusObservation,
};

/// Fixed scheduling bounds controlled by the gateway operator, not a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayExecutionPolicy {
    pub lease_seconds: u64,
    pub retry_seconds: u64,
}

impl GatewayExecutionPolicy {
    pub fn conservative() -> Self {
        Self {
            lease_seconds: 60,
            retry_seconds: 30,
        }
    }

    fn validate(self) -> Result<Self, GatewayExecutionError> {
        if self.lease_seconds == 0
            || self.lease_seconds > 60 * 60
            || self.retry_seconds == 0
            || self.retry_seconds > 60 * 60
        {
            return Err(GatewayExecutionError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// A provider failure classification without provider-controlled diagnostic
/// text. Endpoint URLs, authorization material, and RPC bodies cannot enter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayProviderFailure {
    #[error("gateway provider is temporarily unavailable")]
    Transient,
    #[error("gateway provider permanently rejected the request")]
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayProviderStatus {
    Accepted,
    Rejected,
}

/// An RPC transport observation correlated to the exact submitted hash.
/// It is never transaction confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RelayProviderObservation {
    tx_hash: [u8; 32],
    status: RelayProviderStatus,
}

impl std::fmt::Debug for RelayProviderObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayProviderObservation")
            .field("status", &self.status)
            .finish()
    }
}

impl RelayProviderObservation {
    pub fn new(tx_hash: [u8; 32], status: RelayProviderStatus) -> Self {
        Self { tx_hash, status }
    }

    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx_hash
    }

    pub fn status(&self) -> RelayProviderStatus {
        self.status
    }
}

/// Narrow provider boundary for a standalone or supervised gateway service.
///
/// Implementations may submit exact signed bytes and acquire proof material,
/// but cannot ask this core to sign, install checkpoints, select arbitrary RPC
/// methods, or manufacture a `GatewayBundle` from unchecked bytes.
pub trait GatewayExecutionProvider {
    fn submit_signed_relay(
        &mut self,
        relay: &AcceptedSignedRelay,
    ) -> Result<RelayProviderObservation, GatewayProviderFailure>;

    fn fetch_verified_evidence(
        &mut self,
        request: &AcceptedEvidenceRequest,
    ) -> Result<GatewayBundle, GatewayProviderFailure>;

    /// Samples exact transaction presence and execution heads through the
    /// provider's fixed RPC surface. This is never receipt evidence or
    /// Ethereum confirmation.
    fn observe_transaction_status(
        &mut self,
        request: &AcceptedTransactionStatusRequest,
    ) -> Result<TransactionStatusObservation, GatewayProviderFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayExecutionOutcome {
    Idle,
    Deferred,
    Completed(GatewayStoredResult),
}

/// Redacted executor failure. Provider diagnostics never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayExecutionError {
    #[error("gateway execution policy is invalid")]
    InvalidPolicy,
    #[error("gateway durable state is unavailable")]
    Admission(#[from] GatewayAdmissionError),
    #[error("retained gateway work is invalid")]
    RetainedMessage(#[from] GatewayMessageError),
}

/// Executes at most one durable request per call.
pub struct GatewayExecutor {
    requester: [u8; 16],
    policy: GatewayExecutionPolicy,
    response_encoder: GatewayRelayGuard,
}

impl GatewayExecutor {
    pub fn new(
        requester: [u8; 16],
        policy: GatewayExecutionPolicy,
    ) -> Result<Self, GatewayExecutionError> {
        let policy = policy.validate()?;
        let response_encoder = GatewayRelayGuard::new(requester, GatewayRateLimit::conservative())
            .map_err(|_| GatewayExecutionError::InvalidPolicy)?;
        Ok(Self {
            requester,
            policy,
            response_encoder,
        })
    }

    pub fn execute_next(
        &self,
        admission: &mut DurableGatewayAdmission,
        provider: &mut impl GatewayExecutionProvider,
        now_unix: u64,
    ) -> Result<GatewayExecutionOutcome, GatewayExecutionError> {
        let Some(lease) =
            admission.lease_next(self.requester, now_unix, self.policy.lease_seconds)?
        else {
            return Ok(GatewayExecutionOutcome::Idle);
        };

        let message = lease.validated_message()?;
        let execution: Result<(GatewayResultKind, Vec<u8>, Vec<u8>), ExecutionFailure> =
            match message {
                GatewayMessageOutcome::SignedRelay(relay) => provider
                    .submit_signed_relay(&relay)
                    .map_err(ExecutionFailure::Provider)
                    .and_then(|observation| self.relay_response(&relay, observation)),
                GatewayMessageOutcome::EvidenceRequest(request) => provider
                    .fetch_verified_evidence(&request)
                    .map_err(ExecutionFailure::Provider)
                    .and_then(|bundle| {
                        let manifest = self
                            .response_encoder
                            .evidence_manifest(&request, &bundle)
                            .map_err(|_| ExecutionFailure::Message)?;
                        let response = self
                            .response_encoder
                            .staged_evidence_response(&request, &bundle)
                            .map_err(|_| ExecutionFailure::Message)?;
                        Ok((GatewayResultKind::Evidence, manifest, response))
                    }),
                GatewayMessageOutcome::TransactionStatus(request) => provider
                    .observe_transaction_status(&request)
                    .map_err(ExecutionFailure::Provider)
                    .and_then(|observation| {
                        let response = self
                            .response_encoder
                            .transaction_status_observation(&request, observation)
                            .map_err(|_| ExecutionFailure::Message)?;
                        Ok((GatewayResultKind::TransactionStatus, Vec::new(), response))
                    }),
                GatewayMessageOutcome::IgnoredUnauthenticated => {
                    // Durable admission never persists unauthenticated work.
                    Err(ExecutionFailure::Permanent)
                }
                GatewayMessageOutcome::BulkApproval(_) => Err(ExecutionFailure::Permanent),
            };

        match execution {
            Ok((kind, manifest, response)) => admission
                .complete_with_result(&lease, kind, &manifest, &response, now_unix)
                .map(GatewayExecutionOutcome::Completed)
                .map_err(Into::into),
            Err(ExecutionFailure::Provider(GatewayProviderFailure::Transient)) => {
                self.defer_or_expire(admission, &lease, now_unix)
            }
            Err(ExecutionFailure::Provider(GatewayProviderFailure::Permanent))
            | Err(ExecutionFailure::Permanent)
            | Err(ExecutionFailure::Message) => admission
                .complete_with_result(
                    &lease,
                    GatewayResultKind::PermanentFailure,
                    &[],
                    &[],
                    now_unix,
                )
                .map(GatewayExecutionOutcome::Completed)
                .map_err(Into::into),
        }
    }

    fn relay_response(
        &self,
        relay: &AcceptedSignedRelay,
        observation: RelayProviderObservation,
    ) -> Result<(GatewayResultKind, Vec<u8>, Vec<u8>), ExecutionFailure> {
        if observation.tx_hash != relay.tx_hash() {
            return Err(ExecutionFailure::Permanent);
        }
        let (kind, wire) = match observation.status {
            RelayProviderStatus::Accepted => (
                GatewayResultKind::RelayAccepted,
                RelayObservation::RpcAccepted,
            ),
            RelayProviderStatus::Rejected => (
                GatewayResultKind::RelayRejected,
                RelayObservation::RpcRejected,
            ),
        };
        Ok((
            kind,
            Vec::new(),
            self.response_encoder.relay_observation(relay, wire),
        ))
    }

    fn defer_or_expire(
        &self,
        admission: &mut DurableGatewayAdmission,
        lease: &crate::GatewayLease,
        now_unix: u64,
    ) -> Result<GatewayExecutionOutcome, GatewayExecutionError> {
        let retry_at = now_unix.checked_add(self.policy.retry_seconds);
        if retry_at.is_none_or(|retry_at| retry_at >= lease.job().expires_at_unix()) {
            return admission
                .complete_with_result(
                    lease,
                    GatewayResultKind::PermanentFailure,
                    &[],
                    &[],
                    now_unix,
                )
                .map(GatewayExecutionOutcome::Completed)
                .map_err(Into::into);
        }
        admission.defer_until(lease, retry_at.expect("checked above"))?;
        Ok(GatewayExecutionOutcome::Deferred)
    }
}

enum ExecutionFailure {
    Provider(GatewayProviderFailure),
    Message,
    Permanent,
}

impl From<GatewayProviderFailure> for ExecutionFailure {
    fn from(value: GatewayProviderFailure) -> Self {
        Self::Provider(value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::Path;

    use base64::Engine;
    use ratspeak_eth_verifier::{
        BeaconCheckpointRoot, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, Verifier,
    };

    use super::*;
    use crate::messaging::{
        AuthenticatedGatewayEnvelope, DurableGatewayOutcome, MessagingEvidenceKind,
        encode_test_contextual_evidence_request, encode_test_evidence_request,
        encode_test_signed_relay, encode_test_transaction_status_request,
    };
    use crate::{
        SepoliaGatewayBuilder, TransactionPresence, TransactionStatusHead,
        UntrustedConsensusRpcInput, UntrustedExecutionAncestryRpcInput,
        UntrustedExecutionHeaderRpcInput, UntrustedTxReceiptProofRpcInput,
    };

    const REQUESTER: [u8; 16] = [0x31; 16];
    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    struct FixtureProvider {
        relays: VecDeque<Result<RelayProviderObservation, GatewayProviderFailure>>,
        evidence: VecDeque<Result<GatewayBundle, GatewayProviderFailure>>,
        statuses: VecDeque<Result<TransactionStatusObservation, GatewayProviderFailure>>,
        submitted: Vec<Vec<u8>>,
    }

    impl FixtureProvider {
        fn empty() -> Self {
            Self {
                relays: VecDeque::new(),
                evidence: VecDeque::new(),
                statuses: VecDeque::new(),
                submitted: Vec::new(),
            }
        }
    }

    impl GatewayExecutionProvider for FixtureProvider {
        fn submit_signed_relay(
            &mut self,
            relay: &AcceptedSignedRelay,
        ) -> Result<RelayProviderObservation, GatewayProviderFailure> {
            self.submitted.push(relay.raw_transaction().to_vec());
            self.relays.pop_front().expect("relay fixture")
        }

        fn observe_transaction_status(
            &mut self,
            _request: &AcceptedTransactionStatusRequest,
        ) -> Result<TransactionStatusObservation, GatewayProviderFailure> {
            self.statuses.pop_front().expect("status fixture")
        }

        fn fetch_verified_evidence(
            &mut self,
            _request: &AcceptedEvidenceRequest,
        ) -> Result<GatewayBundle, GatewayProviderFailure> {
            self.evidence.pop_front().expect("evidence fixture")
        }
    }

    fn open(path: &Path) -> DurableGatewayAdmission {
        DurableGatewayAdmission::open(path, [REQUESTER], GatewayRateLimit::conservative()).unwrap()
    }

    fn admit(store: &mut DurableGatewayAdmission, bytes: &[u8]) {
        assert!(matches!(
            store
                .admit_persisted_attachment(
                    AuthenticatedGatewayEnvelope::from_verified_lxmf(REQUESTER, bytes),
                    10,
                )
                .unwrap(),
            DurableGatewayOutcome::Queued(_)
        ));
    }

    fn raw_native_transfer() -> Vec<u8> {
        alloy_primitives::hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap()
    }

    fn relay_hash(raw: &[u8]) -> [u8; 32] {
        use alloy_consensus::TxEnvelope;
        use alloy_eips::eip2718::Decodable2718;
        let mut remaining = raw;
        let tx = TxEnvelope::decode_2718(&mut remaining).unwrap();
        assert!(remaining.is_empty());
        tx.tx_hash().0
    }

    fn decode_fixture(value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .unwrap()
    }

    fn receipt_builder_and_input() -> (SepoliaGatewayBuilder, UntrustedTxReceiptProofRpcInput) {
        let execution_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-execution-header-11574048.rseth.b64"
        ));
        let execution = Verifier::sepolia()
            .parse_execution_header_proof(&execution_bytes)
            .unwrap();
        let receipt_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        let receipt = Verifier::sepolia()
            .parse_tx_receipt_proof(&receipt_bytes)
            .unwrap();
        let builder = SepoliaGatewayBuilder::from_untrusted_rpc_at_unix(
            &BeaconCheckpointRoot::sepolia(CHECKPOINT_ROOT),
            &UntrustedConsensusRpcInput {
                chain_id: SEPOLIA_CHAIN_ID,
                network: SEPOLIA_NETWORK.to_owned(),
                captured_at_unix: 0,
                bootstrap_ssz: decode_fixture(include_str!(
                    "../../ratspeak-eth-verifier/tests/fixtures/sepolia-bootstrap-343888.ssz.b64"
                )),
                updates_ssz: Vec::new(),
                finality_update_ssz: None,
            },
            &UntrustedExecutionHeaderRpcInput {
                chain_id: execution.chain_id,
                network: execution.network,
                captured_at_unix: execution.created_at_unix,
                rlp_header: execution.rlp_header,
            },
            crate::FIXTURE_NOW_UNIX,
        )
        .unwrap();
        (
            builder,
            UntrustedTxReceiptProofRpcInput {
                chain_id: receipt.chain_id,
                network: receipt.network,
                captured_at_unix: receipt.created_at_unix,
                block_number: receipt.block_number,
                block_hash: receipt.block_hash,
                tx_hash: receipt.tx_hash,
                tx_index: receipt.tx_index,
                raw_tx: receipt.raw_tx,
                receipt: receipt.receipt,
                transactions_root: receipt.transactions_root,
                receipts_root: receipt.receipts_root,
                tx_proof: receipt.tx_proof,
                receipt_proof: receipt.receipt_proof,
            },
        )
    }

    fn verified_receipt_bundle() -> GatewayBundle {
        let (builder, receipt) = receipt_builder_and_input();
        builder.build_tx_receipt_proof(&receipt).unwrap()
    }

    fn verified_finalized_package() -> GatewayBundle {
        let (builder, receipt) = receipt_builder_and_input();
        let ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: receipt.captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: receipt.block_number,
            target_block_hash: receipt.block_hash,
            rlp_headers: Vec::new(),
        };
        builder
            .build_finalized_receipt_evidence(&ancestry, &receipt)
            .unwrap()
    }

    #[test]
    fn exact_relay_observation_is_persisted_and_remains_non_authoritative() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let raw = raw_native_transfer();
        let hash = relay_hash(&raw);
        let request_id = [0x41; 16];
        let message = encode_test_signed_relay(request_id, 1_000, &raw);
        let mut store = open(&path);
        admit(&mut store, &message);
        let mut provider = FixtureProvider::empty();
        provider.relays.push_back(Ok(RelayProviderObservation::new(
            hash,
            RelayProviderStatus::Accepted,
        )));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected completion")
        };
        assert_eq!(provider.submitted, [raw]);
        assert_eq!(result.kind(), GatewayResultKind::RelayAccepted);
        assert!(result.manifest().is_empty());
        assert!(!result.response().is_empty());
        drop(store);

        let reopened = open(&path);
        let recovered = reopened
            .completed_result(REQUESTER, request_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered, result);
        assert_eq!(recovered.kind(), GatewayResultKind::RelayAccepted);
    }

    #[test]
    fn transaction_status_observation_is_durable_and_replayed_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let request_id = [0x61; 16];
        let tx_hash = [0x62; 32];
        let mut store = open(&path);
        admit(
            &mut store,
            &encode_test_transaction_status_request(request_id, 1_000, tx_hash),
        );
        let mut provider = FixtureProvider::empty();
        provider
            .statuses
            .push_back(Ok(TransactionStatusObservation::new(
                tx_hash,
                TransactionPresence::Included,
                99,
                [0x63; 32],
                TransactionStatusHead::new(102, [0x64; 32]).unwrap(),
                TransactionStatusHead::new(101, [0x65; 32]).unwrap(),
                TransactionStatusHead::new(100, [0x66; 32]).unwrap(),
            )
            .unwrap()));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected completion");
        };
        assert_eq!(result.kind(), GatewayResultKind::TransactionStatus);
        assert_eq!(result.response().len(), 226);
        assert_eq!(result.response()[16], 9);
        drop(store);
        let reopened = open(&path);
        assert_eq!(
            reopened.completed_result(REQUESTER, request_id).unwrap(),
            Some(result)
        );
    }

    #[test]
    fn failed_transaction_status_is_durable_and_replayed_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let request_id = [0x67; 16];
        let tx_hash = [0x68; 32];
        let mut store = open(&path);
        admit(
            &mut store,
            &encode_test_transaction_status_request(request_id, 1_000, tx_hash),
        );
        let mut provider = FixtureProvider::empty();
        provider
            .statuses
            .push_back(Err(GatewayProviderFailure::Permanent));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected completion");
        };
        assert_eq!(result.kind(), GatewayResultKind::PermanentFailure);
        assert!(result.manifest().is_empty());
        assert!(result.response().is_empty());
        drop(store);

        let reopened = open(&path);
        assert_eq!(
            reopened.completed_result(REQUESTER, request_id).unwrap(),
            Some(result)
        );
    }

    #[test]
    fn false_rpc_hash_is_never_recorded_as_acceptance() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("gateway.sqlite"));
        let raw = raw_native_transfer();
        let request_id = [0x42; 16];
        admit(
            &mut store,
            &encode_test_signed_relay(request_id, 1_000, &raw),
        );
        let mut provider = FixtureProvider::empty();
        provider.relays.push_back(Ok(RelayProviderObservation::new(
            [0x99; 32],
            RelayProviderStatus::Accepted,
        )));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected terminal failure")
        };
        assert_eq!(result.kind(), GatewayResultKind::PermanentFailure);
        assert!(result.response().is_empty());
    }

    #[test]
    fn transient_failure_defers_across_restart_then_retries_exact_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let raw = raw_native_transfer();
        let hash = relay_hash(&raw);
        let mut store = open(&path);
        admit(
            &mut store,
            &encode_test_signed_relay([0x43; 16], 1_000, &raw),
        );
        let policy = GatewayExecutionPolicy {
            lease_seconds: 10,
            retry_seconds: 20,
        };
        let executor = GatewayExecutor::new(REQUESTER, policy).unwrap();
        let mut transient = FixtureProvider::empty();
        transient
            .relays
            .push_back(Err(GatewayProviderFailure::Transient));
        assert_eq!(
            executor
                .execute_next(&mut store, &mut transient, 11)
                .unwrap(),
            GatewayExecutionOutcome::Deferred
        );
        drop(store);

        let mut reopened = open(&path);
        let mut provider = FixtureProvider::empty();
        assert_eq!(
            executor
                .execute_next(&mut reopened, &mut provider, 30)
                .unwrap(),
            GatewayExecutionOutcome::Idle
        );
        provider.relays.push_back(Ok(RelayProviderObservation::new(
            hash,
            RelayProviderStatus::Accepted,
        )));
        assert!(matches!(
            executor.execute_next(&mut reopened, &mut provider, 31),
            Ok(GatewayExecutionOutcome::Completed(_))
        ));
        assert_eq!(provider.submitted, [raw]);
    }

    #[test]
    fn finalized_exact_receipt_bundle_is_bound_to_request_and_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let mut store = open(&path);
        let bundle = verified_receipt_bundle();
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(bundle.bytes())
            .unwrap();
        let request_id = [0x44; 16];
        admit(
            &mut store,
            &encode_test_evidence_request(
                request_id,
                MessagingEvidenceKind::ReceiptProof,
                parsed.tx_hash,
                u32::try_from(bundle.bytes().len() + 128).unwrap(),
                true,
                1_000,
            ),
        );
        let mut provider = FixtureProvider::empty();
        provider.evidence.push_back(Ok(bundle.clone()));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected evidence")
        };
        assert_eq!(result.kind(), GatewayResultKind::Evidence);
        assert!(!result.manifest().is_empty());
        assert!(result.response().ends_with(bundle.bytes()));
        drop(store);
        let store = open(&path);
        assert_eq!(
            store
                .completed_result(REQUESTER, request_id)
                .unwrap()
                .unwrap(),
            result
        );
    }

    #[test]
    fn composite_finalized_receipt_survives_executor_restart_with_exact_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let bundle = verified_finalized_package();
        let tx_hash = Verifier::sepolia()
            .parse_finalized_receipt_evidence(bundle.bytes())
            .unwrap()
            .finalized_receipt()
            .receipt_proof
            .tx_hash;
        let request_id = [0x48; 16];
        let wire = encode_test_contextual_evidence_request(
            request_id,
            MessagingEvidenceKind::FinalizedReceiptPackage,
            tx_hash,
            343_888,
            CHECKPOINT_ROOT,
            bundle.bytes().len() as u32,
            true,
            1_000,
        );
        let mut store = open(&path);
        admit(&mut store, &wire);
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let mut transient = FixtureProvider::empty();
        transient
            .evidence
            .push_back(Err(GatewayProviderFailure::Transient));
        assert_eq!(
            executor
                .execute_next(&mut store, &mut transient, 11)
                .unwrap(),
            GatewayExecutionOutcome::Deferred
        );
        assert!(
            store
                .completed_result(REQUESTER, request_id)
                .unwrap()
                .is_none()
        );
        drop(store);

        let mut store = open(&path);
        let mut provider = FixtureProvider::empty();
        provider.evidence.push_back(Ok(bundle.clone()));
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 41)
            .unwrap()
        else {
            panic!("expected composite evidence")
        };
        assert_eq!(result.kind(), GatewayResultKind::Evidence);
        assert!(result.response().ends_with(bundle.bytes()));
        drop(store);
        let reopened = open(&path);
        assert_eq!(
            reopened
                .completed_result(REQUESTER, request_id)
                .unwrap()
                .unwrap(),
            result
        );
    }

    #[test]
    fn mismatched_evidence_never_becomes_a_response() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open(&directory.path().join("gateway.sqlite"));
        let bundle = verified_receipt_bundle();
        admit(
            &mut store,
            &encode_test_evidence_request(
                [0x45; 16],
                MessagingEvidenceKind::ReceiptProof,
                [0x77; 32],
                u32::try_from(bundle.bytes().len() + 128).unwrap(),
                true,
                1_000,
            ),
        );
        let mut provider = FixtureProvider::empty();
        provider.evidence.push_back(Ok(bundle));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        let GatewayExecutionOutcome::Completed(result) = executor
            .execute_next(&mut store, &mut provider, 11)
            .unwrap()
        else {
            panic!("expected terminal failure")
        };
        assert_eq!(result.kind(), GatewayResultKind::PermanentFailure);
        assert!(result.response().is_empty());
    }

    #[test]
    fn swapped_valid_manifests_fail_request_correlation_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let mut store = open(&path);
        let bundle = verified_receipt_bundle();
        let tx_hash = Verifier::sepolia()
            .parse_tx_receipt_proof(bundle.bytes())
            .unwrap()
            .tx_hash;
        let request_ids = [[0x46; 16], [0x47; 16]];
        for request_id in request_ids {
            admit(
                &mut store,
                &encode_test_evidence_request(
                    request_id,
                    MessagingEvidenceKind::ReceiptProof,
                    tx_hash,
                    u32::try_from(bundle.bytes().len() + 128).unwrap(),
                    true,
                    1_000,
                ),
            );
        }
        let mut provider = FixtureProvider::empty();
        provider.evidence.push_back(Ok(bundle.clone()));
        provider.evidence.push_back(Ok(bundle));
        let executor =
            GatewayExecutor::new(REQUESTER, GatewayExecutionPolicy::conservative()).unwrap();
        for now in [11, 12] {
            assert!(matches!(
                executor.execute_next(&mut store, &mut provider, now),
                Ok(GatewayExecutionOutcome::Completed(_))
            ));
        }
        drop(store);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let first: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT manifest, manifest_digest FROM gateway_job_results WHERE request_id = ?1",
                [request_ids[0].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let second: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT manifest, manifest_digest FROM gateway_job_results WHERE request_id = ?1",
                [request_ids[1].as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE gateway_job_results SET manifest = ?1, manifest_digest = ?2
                  WHERE request_id = ?3",
                rusqlite::params![second.0, second.1, request_ids[0].as_slice()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE gateway_job_results SET manifest = ?1, manifest_digest = ?2
                  WHERE request_id = ?3",
                rusqlite::params![first.0, first.1, request_ids[1].as_slice()],
            )
            .unwrap();
        drop(connection);

        let reopened = open(&path);
        assert_eq!(
            reopened
                .completed_result(REQUESTER, request_ids[0])
                .unwrap_err(),
            GatewayAdmissionError::Storage
        );
    }

    #[test]
    fn provider_errors_and_observations_are_redacted() {
        let marker = "RPC_PRIVATE_MARKER";
        for rendered in [
            format!("{:?}", GatewayProviderFailure::Transient),
            GatewayProviderFailure::Permanent.to_string(),
            format!(
                "{:?}",
                RelayProviderObservation::new([0x55; 32], RelayProviderStatus::Rejected)
            ),
        ] {
            assert!(!rendered.contains(marker));
            assert!(!rendered.contains(&"55".repeat(32)));
        }
    }
}
