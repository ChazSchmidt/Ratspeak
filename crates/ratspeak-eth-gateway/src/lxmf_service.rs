//! Authenticated LXMF edge for the standalone Ethereum gateway service.
//!
//! This module consumes already-delivered `lxmf-core` messages. It does not
//! own a router, service signing identity, provider credentials, discovery, or
//! delivery acknowledgements. A host turns the sealed outbound intents into
//! ordinary signed LXMF file attachments.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;

use lxmf_core::constants::FIELD_FILE_ATTACHMENTS;
use lxmf_core::message_api::{DeliveryMethod, LxMessage};
use rmpv::Value;
use rns_crypto::ed25519::Ed25519PublicKey;
use sha2::{Digest, Sha256};

use crate::messaging::durable::GatewayReleasePhase;
use crate::{
    AuthenticatedGatewayEnvelope, DurableGatewayAdmission, DurableGatewayOutcome,
    GatewayAdmissionError, GatewayExecutionError, GatewayExecutionOutcome, GatewayExecutionPolicy,
    GatewayExecutionProvider, GatewayJobState, GatewayMessageError, GatewayRateLimit,
    GatewayResultKind, GatewayStoredResult,
};

/// The one native LXMF file name accepted and emitted by this service edge.
pub const GATEWAY_LXMF_ATTACHMENT_NAME: &str = "ratspeak-ethereum.rseth";

const MAX_INBOUND_ATTACHMENT_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GatewayLxmfServiceError {
    #[error("invalid gateway LXMF service configuration")]
    InvalidConfiguration,
    #[error("gateway LXMF signature was not validated")]
    SignatureNotValidated,
    #[error("gateway LXMF requester is not configured")]
    RequesterNotConfigured,
    #[error("gateway LXMF destination does not match the service")]
    WrongDestination,
    #[error("gateway LXMF message binding is invalid")]
    InvalidMessageBinding,
    #[error("gateway LXMF attachment is invalid")]
    InvalidAttachment,
    #[error("gateway durable admission failed")]
    Admission(#[from] GatewayAdmissionError),
    #[error("gateway execution failed")]
    Execution(#[from] GatewayExecutionError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayLxmfFrameKind {
    EvidenceManifest,
    EvidenceResponse,
    RelayObservation,
    TransactionStatusObservation,
    ServiceFailure,
}

/// A host-owned LXMF router can sign and deliver this exact attachment intent.
///
/// Delivery method, next hop, propagation node, receipt, and acknowledgement
/// are deliberately absent. None of them change the Ethereum meaning of the
/// retained frame.
#[derive(Clone)]
pub struct GatewayLxmfOutboundIntent {
    source_hash: [u8; 16],
    destination_hash: [u8; 16],
    frame_kind: GatewayLxmfFrameKind,
    attachment: Vec<u8>,
    release_token: [u8; 32],
}

impl PartialEq for GatewayLxmfOutboundIntent {
    fn eq(&self, other: &Self) -> bool {
        self.source_hash == other.source_hash
            && self.destination_hash == other.destination_hash
            && self.frame_kind == other.frame_kind
            && self.attachment == other.attachment
    }
}

impl Eq for GatewayLxmfOutboundIntent {}

impl std::fmt::Debug for GatewayLxmfOutboundIntent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayLxmfOutboundIntent")
            .field("frame_kind", &self.frame_kind)
            .field("attachment_len", &self.attachment.len())
            .finish()
    }
}

impl GatewayLxmfOutboundIntent {
    pub fn source_hash(&self) -> [u8; 16] {
        self.source_hash
    }

    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }

    pub fn frame_kind(&self) -> GatewayLxmfFrameKind {
        self.frame_kind
    }

    pub fn attachment_name(&self) -> &'static str {
        GATEWAY_LXMF_ATTACHMENT_NAME
    }

    pub fn attachment(&self) -> &[u8] {
        &self.attachment
    }

    /// Opaque durable handoff generation shared by every frame in one batch.
    pub fn release_token(&self) -> [u8; 32] {
        self.release_token
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayLxmfServiceOutcome {
    /// Work was admitted or remained pending without a protocol frame.
    AcceptedNoOutput,
    /// The provider reported a transient failure and durable work was deferred.
    Deferred,
    /// Ordered generic LXMF attachments. Evidence is always manifest first.
    Outbound(Vec<GatewayLxmfOutboundIntent>),
}

/// Restart-safe authenticated gateway service core.
///
/// This type is idle until a host supplies an inbound LXMF message. It has no
/// discovery, heartbeat, or transport-maintenance behavior.
pub struct GatewayLxmfService {
    service_destination_hash: [u8; 16],
    configured_requesters: HashMap<[u8; 16], Ed25519PublicKey>,
    execution_policy: GatewayExecutionPolicy,
    admission: DurableGatewayAdmission,
    recovery_result_rowid: i64,
}

impl std::fmt::Debug for GatewayLxmfService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayLxmfService")
            .field(
                "configured_requester_count",
                &self.configured_requesters.len(),
            )
            .finish_non_exhaustive()
    }
}

impl GatewayLxmfService {
    /// Open the service with an out-of-band binding from each allowed LXMF
    /// source hash to its exact Ed25519 signing public key. The adapter
    /// re-verifies every current message instead of trusting its public
    /// `signature_validated` field as a capability.
    pub fn open(
        path: &Path,
        service_destination_hash: [u8; 16],
        requester_verification_keys: impl IntoIterator<Item = ([u8; 16], [u8; 32])>,
        rate_limit: GatewayRateLimit,
        execution_policy: GatewayExecutionPolicy,
    ) -> Result<Self, GatewayLxmfServiceError> {
        let mut configured_requesters = HashMap::new();
        for (source_hash, public_key) in requester_verification_keys {
            let public_key = Ed25519PublicKey::from_bytes(&public_key)
                .map_err(|_| GatewayLxmfServiceError::InvalidConfiguration)?;
            if configured_requesters
                .insert(source_hash, public_key)
                .is_some()
            {
                return Err(GatewayLxmfServiceError::InvalidConfiguration);
            }
        }
        if service_destination_hash == [0; 16]
            || configured_requesters.is_empty()
            || configured_requesters.contains_key(&[0; 16])
            || configured_requesters.contains_key(&service_destination_hash)
        {
            return Err(GatewayLxmfServiceError::InvalidConfiguration);
        }
        // Validate the execution policy without keeping an executor or any
        // provider state alive while the service is idle.
        for requester in configured_requesters.keys() {
            crate::GatewayExecutor::new(*requester, execution_policy)?;
        }
        let admission =
            DurableGatewayAdmission::open(path, configured_requesters.keys().copied(), rate_limit)?;
        Ok(Self {
            service_destination_hash,
            configured_requesters,
            execution_policy,
            admission,
            recovery_result_rowid: 0,
        })
    }

    /// Authenticate, admit, and execute at most one request for this exact
    /// requester. Provider responses are converted only into sealed outbound
    /// LXMF attachment intents addressed back to that requester.
    pub fn handle_inbound(
        &mut self,
        message: &LxMessage,
        provider: &mut impl GatewayExecutionProvider,
        now_unix: u64,
    ) -> Result<GatewayLxmfServiceOutcome, GatewayLxmfServiceError> {
        let envelope = self.authenticate(message)?;
        let requester = message.source_hash;
        let admitted = self
            .admission
            .admit_persisted_attachment(envelope, now_unix)?;

        if let DurableGatewayOutcome::BulkApproved(result) = &admitted {
            return self.outbound_for_approved_bulk(requester, result, now_unix);
        }

        if matches!(
            admitted,
            DurableGatewayOutcome::Duplicate(GatewayJobState::Completed)
        ) {
            // Admission already charged and decoded this exact attachment.
            let request_id = envelope
                .request_id()
                .map_err(map_message_error_to_admission)?;
            let result = self
                .admission
                .completed_result(requester, request_id)?
                .ok_or(GatewayLxmfServiceError::Admission(
                    GatewayAdmissionError::InvalidState,
                ))?;
            return self.outbound_for_result(requester, &result, now_unix);
        }
        if matches!(admitted, DurableGatewayOutcome::IgnoredUnauthenticated) {
            return Err(GatewayLxmfServiceError::RequesterNotConfigured);
        }

        match self.execute_for_requester(requester, provider, now_unix)? {
            GatewayExecutionOutcome::Idle => Ok(GatewayLxmfServiceOutcome::AcceptedNoOutput),
            GatewayExecutionOutcome::Deferred => Ok(GatewayLxmfServiceOutcome::Deferred),
            GatewayExecutionOutcome::Completed(result) => {
                self.outbound_for_result(requester, &result, now_unix)
            }
        }
    }

    /// Resume one retained request without requiring requester retransmission.
    ///
    /// Pending or deferred work is tried first in deterministic requester
    /// order. If there is none, a completed result receives a durably bounded
    /// handoff attempt. The attempt is consumed before bytes leave this core,
    /// so crashes and a relay that refuses purge cannot amplify output without
    /// bound. Receivers must remain duplicate-safe.
    pub fn resume_next(
        &mut self,
        provider: &mut impl GatewayExecutionProvider,
        now_unix: u64,
    ) -> Result<GatewayLxmfServiceOutcome, GatewayLxmfServiceError> {
        let mut requesters: Vec<_> = self.configured_requesters.keys().copied().collect();
        requesters.sort_unstable();
        for requester in requesters {
            match self.execute_for_requester(requester, provider, now_unix)? {
                GatewayExecutionOutcome::Idle => {}
                GatewayExecutionOutcome::Deferred => {
                    return Ok(GatewayLxmfServiceOutcome::Deferred);
                }
                GatewayExecutionOutcome::Completed(result) => {
                    return self.outbound_for_result(requester, &result, now_unix);
                }
            }
        }
        let (rowid, result) = self
            .admission
            .completed_result_after(self.recovery_result_rowid, now_unix)?;
        self.recovery_result_rowid = rowid;
        let Some(result) = result else {
            return Ok(GatewayLxmfServiceOutcome::AcceptedNoOutput);
        };
        self.outbound_for_result(result.requester_source_hash(), &result, now_unix)
    }

    fn execute_for_requester(
        &mut self,
        requester: [u8; 16],
        provider: &mut impl GatewayExecutionProvider,
        now_unix: u64,
    ) -> Result<GatewayExecutionOutcome, GatewayLxmfServiceError> {
        let executor = crate::GatewayExecutor::new(requester, self.execution_policy)?;
        executor
            .execute_next(&mut self.admission, provider, now_unix)
            .map_err(Into::into)
    }

    fn authenticate<'a>(
        &self,
        message: &'a LxMessage,
    ) -> Result<AuthenticatedGatewayEnvelope<'a>, GatewayLxmfServiceError> {
        if !message.signature_validated
            || message.signature.is_none()
            || message.wire_payload.is_some()
        {
            return Err(GatewayLxmfServiceError::SignatureNotValidated);
        }
        if !message.incoming || message.source_blackholed || message.unverified_reason.is_some() {
            return Err(GatewayLxmfServiceError::InvalidMessageBinding);
        }
        if message.destination_hash != self.service_destination_hash {
            return Err(GatewayLxmfServiceError::WrongDestination);
        }
        let requester_public_key = self
            .configured_requesters
            .get(&message.source_hash)
            .ok_or(GatewayLxmfServiceError::RequesterNotConfigured)?;
        if !matches!(
            message.method,
            DeliveryMethod::Opportunistic | DeliveryMethod::Direct | DeliveryMethod::Propagated
        ) {
            return Err(GatewayLxmfServiceError::InvalidMessageBinding);
        }
        if !message.title.is_empty()
            || !message.content.is_empty()
            || message.fields.len() != 1
            || !message.fields.contains_key(&FIELD_FILE_ATTACHMENTS)
            || message.msgpack_field_ids.len() != 1
            || !message.msgpack_field_ids.contains(&FIELD_FILE_ATTACHMENTS)
        {
            return Err(GatewayLxmfServiceError::InvalidAttachment);
        }
        // Bound and structurally validate the only potentially large field
        // before cloning/re-encoding the signed payload for its binding check.
        let attachment = exact_attachment(message)?;
        let mut verified_current_message = message.clone();
        if !verified_current_message.verify(requester_public_key) {
            return Err(GatewayLxmfServiceError::SignatureNotValidated);
        }
        if message.hash.is_none()
            || message.hash != message.message_id
            || current_message_id(message)? != message.message_id.expect("checked above")
        {
            return Err(GatewayLxmfServiceError::InvalidMessageBinding);
        }

        Ok(AuthenticatedGatewayEnvelope::from_lxmf_adapter(
            message.source_hash,
            attachment,
        ))
    }

    fn outbound_for_result(
        &mut self,
        authenticated_requester: [u8; 16],
        result: &GatewayStoredResult,
        now_unix: u64,
    ) -> Result<GatewayLxmfServiceOutcome, GatewayLxmfServiceError> {
        if result.requester_source_hash() != authenticated_requester {
            return Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::InvalidState,
            ));
        }
        let bulk = result.kind() == GatewayResultKind::Evidence
            && crate::messaging::evidence_response_requires_bulk_approval(result.response())
                .map_err(map_message_error_to_admission)?;
        let approved = bulk && self.admission.bulk_result_is_approved(result)?;
        let phase = match result.kind() {
            GatewayResultKind::Evidence if bulk && !approved => GatewayReleasePhase::BulkManifest,
            GatewayResultKind::Evidence => GatewayReleasePhase::Evidence,
            GatewayResultKind::RelayAccepted
            | GatewayResultKind::RelayRejected
            | GatewayResultKind::TransactionStatus => GatewayReleasePhase::Relay,
            // Permanent failure is a transport/service result, never an
            // Ethereum-state result. Reuse the bounded terminal release phase
            // used for relay observations so the durable schema and retry cap
            // remain unchanged.
            GatewayResultKind::PermanentFailure => GatewayReleasePhase::Relay,
        };
        let Some(release) = self
            .admission
            .lease_result_release(result, phase, now_unix)?
        else {
            return Ok(GatewayLxmfServiceOutcome::AcceptedNoOutput);
        };
        let intent = |frame_kind, attachment: &[u8]| GatewayLxmfOutboundIntent {
            source_hash: self.service_destination_hash,
            destination_hash: authenticated_requester,
            frame_kind,
            attachment: attachment.to_vec(),
            release_token: release.token,
        };
        let frames = match result.kind() {
            GatewayResultKind::Evidence if bulk && !approved => {
                vec![intent(
                    GatewayLxmfFrameKind::EvidenceManifest,
                    result.manifest(),
                )]
            }
            GatewayResultKind::Evidence if !bulk => vec![
                intent(GatewayLxmfFrameKind::EvidenceManifest, result.manifest()),
                intent(GatewayLxmfFrameKind::EvidenceResponse, result.response()),
            ],
            GatewayResultKind::Evidence => vec![intent(
                GatewayLxmfFrameKind::EvidenceResponse,
                result.response(),
            )],
            GatewayResultKind::RelayAccepted | GatewayResultKind::RelayRejected => vec![intent(
                GatewayLxmfFrameKind::RelayObservation,
                result.response(),
            )],
            GatewayResultKind::TransactionStatus => vec![intent(
                GatewayLxmfFrameKind::TransactionStatusObservation,
                result.response(),
            )],
            GatewayResultKind::PermanentFailure => vec![intent(
                GatewayLxmfFrameKind::ServiceFailure,
                &crate::messaging::service_failure(result.request_id(), result.attachment_digest()),
            )],
        };
        if frames.is_empty() {
            Ok(GatewayLxmfServiceOutcome::AcceptedNoOutput)
        } else {
            Ok(GatewayLxmfServiceOutcome::Outbound(frames))
        }
    }

    fn outbound_for_approved_bulk(
        &mut self,
        authenticated_requester: [u8; 16],
        result: &GatewayStoredResult,
        now_unix: u64,
    ) -> Result<GatewayLxmfServiceOutcome, GatewayLxmfServiceError> {
        if result.requester_source_hash() != authenticated_requester
            || result.kind() != GatewayResultKind::Evidence
            || !crate::messaging::evidence_response_requires_bulk_approval(result.response())
                .map_err(map_message_error_to_admission)?
            || !self.admission.bulk_result_is_approved(result)?
        {
            return Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::InvalidState,
            ));
        }
        let Some(release) =
            self.admission
                .lease_result_release(result, GatewayReleasePhase::Evidence, now_unix)?
        else {
            return Ok(GatewayLxmfServiceOutcome::AcceptedNoOutput);
        };
        Ok(GatewayLxmfServiceOutcome::Outbound(vec![
            GatewayLxmfOutboundIntent {
                source_hash: self.service_destination_hash,
                destination_hash: authenticated_requester,
                frame_kind: GatewayLxmfFrameKind::EvidenceResponse,
                attachment: result.response().to_vec(),
                release_token: release.token,
            },
        ]))
    }

    /// Mark one locally accepted router handoff complete. Transport receipts
    /// remain non-authoritative Ethereum observations.
    pub fn acknowledge_outbound_release(
        &mut self,
        release_token: [u8; 32],
    ) -> Result<(), GatewayLxmfServiceError> {
        self.admission
            .acknowledge_result_release(release_token)
            .map_err(Into::into)
    }
}

fn current_message_id(message: &LxMessage) -> Result<[u8; 32], GatewayLxmfServiceError> {
    let mut canonical = message.clone();
    canonical.stamp = None;
    let payload = canonical
        .pack_payload()
        .map_err(|_| GatewayLxmfServiceError::InvalidMessageBinding)?;
    let mut hasher = Sha256::new();
    hasher.update(message.destination_hash);
    hasher.update(message.source_hash);
    hasher.update(payload);
    Ok(hasher.finalize().into())
}

fn exact_attachment(message: &LxMessage) -> Result<&[u8], GatewayLxmfServiceError> {
    let encoded = message
        .fields
        .get(&FIELD_FILE_ATTACHMENTS)
        .ok_or(GatewayLxmfServiceError::InvalidAttachment)?;
    if encoded.len() > MAX_INBOUND_ATTACHMENT_BYTES.saturating_add(128) {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    }
    let mut cursor = Cursor::new(encoded.as_slice());
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| GatewayLxmfServiceError::InvalidAttachment)?;
    if cursor.position() != encoded.len() as u64 {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    }
    let Value::Array(attachments) = value else {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    };
    let [Value::Array(entry)] = attachments.as_slice() else {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    };
    let [Value::String(name), Value::Binary(bytes)] = entry.as_slice() else {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    };
    if name.as_str() != Some(GATEWAY_LXMF_ATTACHMENT_NAME)
        || bytes.is_empty()
        || bytes.len() > MAX_INBOUND_ATTACHMENT_BYTES
    {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    }
    // Return the canonical bytes owned by `LxMessage`, not the temporary
    // decoded allocation. The lxmf-core accessor borrows that exact range.
    let (borrowed_name, borrowed) = message
        .first_file_attachment()
        .map_err(|_| GatewayLxmfServiceError::InvalidAttachment)?
        .ok_or(GatewayLxmfServiceError::InvalidAttachment)?;
    if borrowed_name != GATEWAY_LXMF_ATTACHMENT_NAME || borrowed != bytes.as_slice() {
        return Err(GatewayLxmfServiceError::InvalidAttachment);
    }
    Ok(borrowed)
}

fn map_message_error_to_admission(error: GatewayMessageError) -> GatewayLxmfServiceError {
    GatewayLxmfServiceError::Admission(GatewayAdmissionError::Message(error))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;
    use base64::Engine;
    use lxmf_core::message_api::{DeliveryRepresentation, MessageState};
    use ratspeak_eth_verifier::{
        BeaconCheckpointRoot, SEPOLIA_CHAIN_ID, SEPOLIA_NETWORK, Verifier,
    };
    use rns_crypto::ed25519::Ed25519PrivateKey;

    use super::*;
    use crate::messaging::{
        MessagingEvidenceKind, encode_test_contextual_evidence_request,
        encode_test_evidence_request, encode_test_signed_relay,
    };
    use crate::{
        AcceptedEvidenceRequest, AcceptedSignedRelay, GatewayBundle, GatewayProviderFailure,
        RelayProviderObservation, RelayProviderStatus, SepoliaGatewayBuilder,
        UntrustedConsensusRpcInput, UntrustedExecutionAncestryRpcInput,
        UntrustedExecutionHeaderRpcInput, UntrustedTxReceiptProofRpcInput,
    };

    const SERVICE: [u8; 16] = [0x21; 16];
    const REQUESTER: [u8; 16] = [0x31; 16];
    const OTHER_REQUESTER: [u8; 16] = [0x32; 16];
    const CHECKPOINT_ROOT: [u8; 32] = [
        0x63, 0x6e, 0x48, 0x99, 0x72, 0x3f, 0xe9, 0x23, 0x7f, 0xbe, 0xe7, 0x09, 0x83, 0x92, 0xb7,
        0xbf, 0x2a, 0x5f, 0x79, 0x04, 0x2c, 0x2c, 0x36, 0xde, 0xda, 0x0c, 0x8c, 0x3a, 0x94, 0xaa,
        0x4d, 0x51,
    ];

    struct FixtureProvider {
        relays: VecDeque<Result<RelayProviderObservation, GatewayProviderFailure>>,
        evidence: VecDeque<Result<GatewayBundle, GatewayProviderFailure>>,
        submitted: Vec<Vec<u8>>,
    }

    impl FixtureProvider {
        fn empty() -> Self {
            Self {
                relays: VecDeque::new(),
                evidence: VecDeque::new(),
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
            _request: &crate::AcceptedTransactionStatusRequest,
        ) -> Result<crate::TransactionStatusObservation, GatewayProviderFailure> {
            Err(GatewayProviderFailure::Permanent)
        }

        fn fetch_verified_evidence(
            &mut self,
            _request: &AcceptedEvidenceRequest,
        ) -> Result<GatewayBundle, GatewayProviderFailure> {
            self.evidence.pop_front().expect("evidence fixture")
        }
    }

    fn open(path: &Path, requesters: impl IntoIterator<Item = [u8; 16]>) -> GatewayLxmfService {
        let public_key = Ed25519PrivateKey::from_bytes(&[0x44; 32])
            .public_key()
            .to_bytes();
        GatewayLxmfService::open(
            path,
            SERVICE,
            requesters
                .into_iter()
                .map(|requester| (requester, public_key)),
            GatewayRateLimit::conservative(),
            GatewayExecutionPolicy::conservative(),
        )
        .unwrap()
    }

    fn signed_inbound(source: [u8; 16], destination: [u8; 16], attachment: &[u8]) -> LxMessage {
        signed_inbound_with_text(source, destination, attachment, "", "")
    }

    fn signed_inbound_with_text(
        source: [u8; 16],
        destination: [u8; 16],
        attachment: &[u8],
        title: &str,
        content: &str,
    ) -> LxMessage {
        let key = Ed25519PrivateKey::from_bytes(&[0x44; 32]);
        let mut outbound =
            LxMessage::new(destination, source, title, content, DeliveryMethod::Direct);
        outbound
            .set_file_attachment_field(GATEWAY_LXMF_ATTACHMENT_NAME, attachment)
            .unwrap();
        outbound.sign(&key).unwrap();
        let packed = outbound.pack().unwrap();
        let mut inbound = LxMessage::unpack(&packed).unwrap();
        assert!(inbound.verify(&key.public_key()));
        inbound
    }

    fn signed_with_attachment_value(source: [u8; 16], value: Value) -> LxMessage {
        let key = Ed25519PrivateKey::from_bytes(&[0x45; 32]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &value).unwrap();
        let mut outbound = LxMessage::new(SERVICE, source, "", "", DeliveryMethod::Direct);
        outbound
            .set_msgpack_field(FIELD_FILE_ATTACHMENTS, encoded)
            .unwrap();
        outbound.sign(&key).unwrap();
        let mut inbound = LxMessage::unpack(&outbound.pack().unwrap()).unwrap();
        assert!(inbound.verify(&key.public_key()));
        inbound
    }

    fn raw_native_transfer() -> Vec<u8> {
        alloy_primitives::hex::decode(
            "02f87583aa36a7078459682f008506fc23ac0082520894111111111111111111111111111111111111111187038d7ea4c6800080c001a014002009527eb67c5524f7883c7104a50a227127c2c2735fc0793ff5439e32eea0726a6fa03c5ea8f8b844b2d314c3bdfb8d7788242f8dd9bf0d098c6e0847b725",
        )
        .unwrap()
    }

    fn relay_hash(raw: &[u8]) -> [u8; 32] {
        let mut remaining = raw;
        let tx = TxEnvelope::decode_2718(&mut remaining).unwrap();
        assert!(remaining.is_empty());
        tx.tx_hash().0
    }

    fn relay_message(request_id: [u8; 16]) -> (LxMessage, Vec<u8>, [u8; 32]) {
        let raw = raw_native_transfer();
        let tx_hash = relay_hash(&raw);
        let wire = encode_test_signed_relay(request_id, 1_000, &raw);
        (signed_inbound(REQUESTER, SERVICE, &wire), raw, tx_hash)
    }

    fn accepted_provider(tx_hash: [u8; 32]) -> FixtureProvider {
        let mut provider = FixtureProvider::empty();
        provider.relays.push_back(Ok(RelayProviderObservation::new(
            tx_hash,
            RelayProviderStatus::Accepted,
        )));
        provider
    }

    fn outbound(outcome: GatewayLxmfServiceOutcome) -> Vec<GatewayLxmfOutboundIntent> {
        let GatewayLxmfServiceOutcome::Outbound(frames) = outcome else {
            panic!("expected outbound frames")
        };
        frames
    }

    fn decode_fixture(value: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .unwrap()
    }

    fn verified_builder() -> SepoliaGatewayBuilder {
        let execution_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-execution-header-11574048.rseth.b64"
        ));
        let execution = Verifier::sepolia()
            .parse_execution_header_proof(&execution_bytes)
            .unwrap();
        SepoliaGatewayBuilder::from_untrusted_rpc(
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
        )
        .unwrap()
    }

    fn verified_receipt_bundle() -> GatewayBundle {
        let receipt_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        let receipt = Verifier::sepolia()
            .parse_tx_receipt_proof(&receipt_bytes)
            .unwrap();
        let builder = verified_builder();
        builder
            .build_tx_receipt_proof(&UntrustedTxReceiptProofRpcInput {
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
            })
            .unwrap()
    }

    fn verified_finalized_package() -> GatewayBundle {
        let receipt_bytes = decode_fixture(include_str!(
            "../../ratspeak-eth-verifier/tests/fixtures/sepolia-receipt-11574048-0.rseth.b64"
        ));
        let receipt = Verifier::sepolia()
            .parse_tx_receipt_proof(&receipt_bytes)
            .unwrap();
        let builder = verified_builder();
        let input = UntrustedTxReceiptProofRpcInput {
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
        };
        let ancestry = UntrustedExecutionAncestryRpcInput {
            chain_id: SEPOLIA_CHAIN_ID,
            network: SEPOLIA_NETWORK.to_owned(),
            captured_at_unix: input.captured_at_unix,
            anchor_block_number: builder.execution_block_number(),
            anchor_block_hash: builder.execution_block_hash(),
            target_block_number: input.block_number,
            target_block_hash: input.block_hash,
            rlp_headers: Vec::new(),
        };
        builder
            .build_finalized_receipt_evidence(&ancestry, &input)
            .unwrap()
    }

    fn bulk_approval(manifest: &[u8], expires_at_unix: u64) -> Vec<u8> {
        let prelude = 7 + 1 + 8 + 1;
        let request_id: [u8; 16] = manifest[prelude..prelude + 16].try_into().unwrap();
        let kind = manifest[prelude + 16];
        let context_len = usize::from(matches!(kind, 5 | 6)) * 40;
        let payload = prelude + 17;
        let digest_offset = payload + context_len;
        let digest: [u8; 32] = manifest[digest_offset..digest_offset + 32]
            .try_into()
            .unwrap();
        let size: [u8; 4] = manifest[digest_offset + 32..digest_offset + 36]
            .try_into()
            .unwrap();
        let mut out = b"RSETHM1".to_vec();
        out.push(1);
        out.extend_from_slice(&SEPOLIA_CHAIN_ID.to_le_bytes());
        out.push(6);
        out.extend_from_slice(&request_id);
        out.extend_from_slice(&expires_at_unix.to_le_bytes());
        out.push(kind);
        out.extend_from_slice(&manifest[payload..digest_offset]);
        out.extend_from_slice(&digest);
        out.extend_from_slice(&size);
        out
    }

    #[test]
    fn signature_source_and_destination_are_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut service = open(&directory.path().join("gateway.sqlite"), [REQUESTER]);
        let (valid, _, _) = relay_message([0x51; 16]);
        let mut provider = FixtureProvider::empty();

        let mut unsigned = valid.clone();
        unsigned.signature_validated = false;
        assert_eq!(
            service.handle_inbound(&unsigned, &mut provider, 10),
            Err(GatewayLxmfServiceError::SignatureNotValidated)
        );
        let mut caller_flag_only = valid.clone();
        caller_flag_only.wire_payload = Some(vec![0x91]);
        assert_eq!(
            service.handle_inbound(&caller_flag_only, &mut provider, 10),
            Err(GatewayLxmfServiceError::SignatureNotValidated)
        );
        let wrong_key = Ed25519PrivateKey::from_bytes(&[0x46; 32]);
        let mut synthesized = LxMessage::new(SERVICE, REQUESTER, "", "", DeliveryMethod::Direct);
        synthesized
            .set_file_attachment_field(
                GATEWAY_LXMF_ATTACHMENT_NAME,
                &encode_test_signed_relay([0x5b; 16], 1_000, &raw_native_transfer()),
            )
            .unwrap();
        synthesized.sign(&wrong_key).unwrap();
        synthesized.incoming = true;
        synthesized.signature_validated = true;
        assert_eq!(
            service.handle_inbound(&synthesized, &mut provider, 10),
            Err(GatewayLxmfServiceError::SignatureNotValidated)
        );

        let wrong_source = signed_inbound(
            OTHER_REQUESTER,
            SERVICE,
            &encode_test_signed_relay([0x52; 16], 1_000, &raw_native_transfer()),
        );
        assert_eq!(
            service.handle_inbound(&wrong_source, &mut provider, 10),
            Err(GatewayLxmfServiceError::RequesterNotConfigured)
        );

        let wrong_destination = signed_inbound(
            REQUESTER,
            [0x22; 16],
            &encode_test_signed_relay([0x53; 16], 1_000, &raw_native_transfer()),
        );
        assert_eq!(
            service.handle_inbound(&wrong_destination, &mut provider, 10),
            Err(GatewayLxmfServiceError::WrongDestination)
        );
    }

    #[test]
    fn post_validation_source_and_attachment_substitution_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let mut service = open(
            &directory.path().join("gateway.sqlite"),
            [REQUESTER, OTHER_REQUESTER],
        );
        let (valid, _, _) = relay_message([0x54; 16]);
        let mut provider = FixtureProvider::empty();

        let mut replaced_source = valid.clone();
        replaced_source.source_hash = OTHER_REQUESTER;
        assert_eq!(
            service.handle_inbound(&replaced_source, &mut provider, 10),
            Err(GatewayLxmfServiceError::SignatureNotValidated)
        );

        let mut replaced_attachment = valid;
        replaced_attachment
            .set_file_attachment_field(GATEWAY_LXMF_ATTACHMENT_NAME, b"substituted")
            .unwrap();
        assert_eq!(
            service.handle_inbound(&replaced_attachment, &mut provider, 10),
            Err(GatewayLxmfServiceError::SignatureNotValidated)
        );
    }

    #[test]
    fn ambiguous_content_command_and_malformed_attachments_have_no_durable_effect() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let limit = GatewayRateLimit {
            window_seconds: 60,
            maximum_requests: 1,
            maximum_requested_bytes: 4 * 1024 * 1024,
        };
        let mut service = GatewayLxmfService::open(
            &path,
            SERVICE,
            [(
                REQUESTER,
                Ed25519PrivateKey::from_bytes(&[0x44; 32])
                    .public_key()
                    .to_bytes(),
            )],
            limit,
            GatewayExecutionPolicy::conservative(),
        )
        .unwrap();
        let relay = encode_test_signed_relay([0x55; 16], 1_000, &raw_native_transfer());
        let mut provider = FixtureProvider::empty();

        let content_command =
            signed_inbound_with_text(REQUESTER, SERVICE, &relay, "", "ethereum relay command");
        assert_eq!(
            service.handle_inbound(&content_command, &mut provider, 10),
            Err(GatewayLxmfServiceError::InvalidAttachment)
        );

        let ambiguous = signed_with_attachment_value(
            REQUESTER,
            Value::Array(vec![
                Value::Array(vec![
                    Value::from(GATEWAY_LXMF_ATTACHMENT_NAME),
                    Value::Binary(relay.clone()),
                ]),
                Value::Array(vec![
                    Value::from(GATEWAY_LXMF_ATTACHMENT_NAME),
                    Value::Binary(relay.clone()),
                ]),
            ]),
        );
        assert_eq!(
            service.handle_inbound(&ambiguous, &mut provider, 10),
            Err(GatewayLxmfServiceError::InvalidAttachment)
        );

        let malformed = signed_with_attachment_value(
            REQUESTER,
            Value::Array(vec![Value::Array(vec![Value::from(
                GATEWAY_LXMF_ATTACHMENT_NAME,
            )])]),
        );
        assert_eq!(
            service.handle_inbound(&malformed, &mut provider, 10),
            Err(GatewayLxmfServiceError::InvalidAttachment)
        );

        let oversized = signed_inbound(
            REQUESTER,
            SERVICE,
            &vec![0x77; MAX_INBOUND_ATTACHMENT_BYTES + 1],
        );
        assert_eq!(
            service.handle_inbound(&oversized, &mut provider, 10),
            Err(GatewayLxmfServiceError::InvalidAttachment)
        );

        let (valid, _, hash) = relay_message([0x56; 16]);
        let mut valid_provider = accepted_provider(hash);
        assert!(matches!(
            service.handle_inbound(&valid, &mut valid_provider, 10),
            Ok(GatewayLxmfServiceOutcome::Outbound(_))
        ));
    }

    #[test]
    fn authenticated_protocol_garbage_consumes_the_durable_attempt_limit() {
        let directory = tempfile::tempdir().unwrap();
        let public_key = Ed25519PrivateKey::from_bytes(&[0x44; 32])
            .public_key()
            .to_bytes();
        let mut service = GatewayLxmfService::open(
            &directory.path().join("gateway.sqlite"),
            SERVICE,
            [(REQUESTER, public_key)],
            GatewayRateLimit {
                window_seconds: 60,
                maximum_requests: 1,
                maximum_requested_bytes: 4 * 1024 * 1024,
            },
            GatewayExecutionPolicy::conservative(),
        )
        .unwrap();
        let garbage = signed_inbound(REQUESTER, SERVICE, b"garbage");
        let mut provider = FixtureProvider::empty();
        assert_eq!(
            service.handle_inbound(&garbage, &mut provider, 10),
            Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::Message(GatewayMessageError::InvalidMessage)
            ))
        );

        let (valid, _, _) = relay_message([0x5c; 16]);
        assert_eq!(
            service.handle_inbound(&valid, &mut provider, 11),
            Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::Message(GatewayMessageError::RateLimited)
            ))
        );
    }

    #[test]
    fn direct_propagated_resource_and_lying_delivery_state_are_non_authoritative() {
        let directory = tempfile::tempdir().unwrap();
        let mut service = open(&directory.path().join("gateway.sqlite"), [REQUESTER]);
        let (direct, raw, hash) = relay_message([0x57; 16]);
        let mut provider = accepted_provider(hash);
        let first = outbound(service.handle_inbound(&direct, &mut provider, 10).unwrap());
        assert_eq!(provider.submitted, [raw]);

        let mut propagated_resource = direct;
        propagated_resource.method = DeliveryMethod::Propagated;
        propagated_resource.representation = DeliveryRepresentation::Resource;
        propagated_resource.state = MessageState::Delivered;
        propagated_resource.progress = 1.0;
        propagated_resource.delivery_attempts = u32::MAX;
        propagated_resource.last_delivery_attempt = f64::MAX;
        propagated_resource.next_delivery_attempt = f64::MAX;
        let mut no_provider_call = FixtureProvider::empty();
        let duplicate = outbound(
            service
                .handle_inbound(&propagated_resource, &mut no_provider_call, 11)
                .unwrap(),
        );
        assert_eq!(duplicate, first);
        assert!(no_provider_call.submitted.is_empty());
    }

    #[test]
    fn duplicate_restart_replays_only_the_exact_stored_requester_response() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let (message, _, hash) = relay_message([0x58; 16]);
        let first = {
            let mut service = open(&path, [REQUESTER, OTHER_REQUESTER]);
            let mut provider = accepted_provider(hash);
            outbound(service.handle_inbound(&message, &mut provider, 10).unwrap())
        };

        let mut reopened = open(&path, [REQUESTER, OTHER_REQUESTER]);
        let mut no_provider_call = FixtureProvider::empty();
        let replayed = outbound(
            reopened
                .handle_inbound(&message, &mut no_provider_call, 11)
                .unwrap(),
        );
        assert_eq!(replayed, first);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].source_hash(), SERVICE);
        assert_eq!(replayed[0].destination_hash(), REQUESTER);
        assert_eq!(
            replayed[0].frame_kind(),
            GatewayLxmfFrameKind::RelayObservation
        );
        assert_eq!(replayed[0].attachment_name(), GATEWAY_LXMF_ATTACHMENT_NAME);
        assert!(no_provider_call.submitted.is_empty());
    }

    #[test]
    fn permanent_provider_failure_returns_exact_bounded_service_notice() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let request_id = [0x59; 16];
        let (message, _, _) = relay_message(request_id);
        let request_bytes = message.first_file_attachment().unwrap().unwrap().1.to_vec();
        let request_digest: [u8; 32] = Sha256::digest(&request_bytes).into();
        let expected = crate::messaging::service_failure(request_id, request_digest);
        let first = {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = FixtureProvider::empty();
            provider
                .relays
                .push_back(Err(GatewayProviderFailure::Permanent));
            let frames = outbound(service.handle_inbound(&message, &mut provider, 10).unwrap());
            assert_eq!(frames.len(), 1);
            assert_eq!(frames[0].frame_kind(), GatewayLxmfFrameKind::ServiceFailure);
            assert_eq!(frames[0].source_hash(), SERVICE);
            assert_eq!(frames[0].destination_hash(), REQUESTER);
            assert_eq!(frames[0].attachment(), expected);
            frames
        };

        for now in [11, 12] {
            let mut reopened = open(&path, [REQUESTER]);
            let recovered = outbound(
                reopened
                    .resume_next(&mut FixtureProvider::empty(), now)
                    .unwrap(),
            );
            assert_eq!(recovered, first);
        }
        let mut reopened = open(&path, [REQUESTER]);
        assert_eq!(
            reopened
                .resume_next(&mut FixtureProvider::empty(), 13)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
    }

    #[test]
    fn restart_resumes_deferred_work_without_requester_retransmission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let public_key = Ed25519PrivateKey::from_bytes(&[0x44; 32])
            .public_key()
            .to_bytes();
        let policy = GatewayExecutionPolicy {
            lease_seconds: 10,
            retry_seconds: 20,
        };
        let (message, raw, hash) = relay_message([0x5d; 16]);
        {
            let mut service = GatewayLxmfService::open(
                &path,
                SERVICE,
                [(REQUESTER, public_key)],
                GatewayRateLimit::conservative(),
                policy,
            )
            .unwrap();
            let mut transient = FixtureProvider::empty();
            transient
                .relays
                .push_back(Err(GatewayProviderFailure::Transient));
            assert_eq!(
                service
                    .handle_inbound(&message, &mut transient, 10)
                    .unwrap(),
                GatewayLxmfServiceOutcome::Deferred
            );
        }

        let mut reopened = GatewayLxmfService::open(
            &path,
            SERVICE,
            [(REQUESTER, public_key)],
            GatewayRateLimit::conservative(),
            policy,
        )
        .unwrap();
        let mut provider = FixtureProvider::empty();
        assert_eq!(
            reopened.resume_next(&mut provider, 29).unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
        provider.relays.push_back(Ok(RelayProviderObservation::new(
            hash,
            RelayProviderStatus::Accepted,
        )));
        let frames = outbound(reopened.resume_next(&mut provider, 30).unwrap());
        assert_eq!(frames.len(), 1);
        assert_eq!(provider.submitted, [raw]);
    }

    #[test]
    fn restart_recovers_completed_intent_once_without_requester_retransmission() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let (message, _, hash) = relay_message([0x5e; 16]);
        let original = {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = accepted_provider(hash);
            outbound(service.handle_inbound(&message, &mut provider, 10).unwrap())
        };

        let mut reopened = open(&path, [REQUESTER]);
        let mut no_provider_call = FixtureProvider::empty();
        let recovered = outbound(reopened.resume_next(&mut no_provider_call, 11).unwrap());
        assert_eq!(recovered, original);
        assert_eq!(
            reopened.resume_next(&mut no_provider_call, 12).unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
        assert!(no_provider_call.submitted.is_empty());
        drop(reopened);

        let mut expired_reopen = open(&path, [REQUESTER]);
        assert_eq!(
            expired_reopen
                .resume_next(&mut no_provider_call, 1_000)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
    }

    #[test]
    fn relay_replay_and_restart_cannot_exceed_durable_release_cap() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let (message, _, hash) = relay_message([0x6e; 16]);
        {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = accepted_provider(hash);
            assert_eq!(
                outbound(service.handle_inbound(&message, &mut provider, 10).unwrap()).len(),
                1
            );
        }
        for now in [11, 12] {
            let mut reopened = open(&path, [REQUESTER]);
            assert_eq!(
                outbound(
                    reopened
                        .handle_inbound(&message, &mut FixtureProvider::empty(), now)
                        .unwrap()
                )
                .len(),
                1
            );
        }
        let mut reopened = open(&path, [REQUESTER]);
        assert_eq!(
            reopened
                .handle_inbound(&message, &mut FixtureProvider::empty(), 13)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
        assert_eq!(
            reopened
                .resume_next(&mut FixtureProvider::empty(), 14)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
    }

    #[test]
    fn acknowledged_release_is_never_repeated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let (message, _, hash) = relay_message([0x6f; 16]);
        let token = {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = accepted_provider(hash);
            let frames = outbound(service.handle_inbound(&message, &mut provider, 10).unwrap());
            let token = frames[0].release_token();
            service.acknowledge_outbound_release(token).unwrap();
            token
        };
        let mut reopened = open(&path, [REQUESTER]);
        reopened.acknowledge_outbound_release(token).unwrap();
        assert_eq!(
            reopened
                .handle_inbound(&message, &mut FixtureProvider::empty(), 11)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
        assert_eq!(
            reopened
                .resume_next(&mut FixtureProvider::empty(), 12)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
    }

    #[test]
    fn evidence_frames_are_ordered_manifest_then_response_for_exact_requester() {
        let directory = tempfile::tempdir().unwrap();
        let mut service = open(&directory.path().join("gateway.sqlite"), [REQUESTER]);
        let bundle = verified_receipt_bundle();
        let parsed = Verifier::sepolia()
            .parse_tx_receipt_proof(bundle.bytes())
            .unwrap();
        let wire = encode_test_evidence_request(
            [0x59; 16],
            MessagingEvidenceKind::ReceiptProof,
            parsed.tx_hash,
            u32::try_from(bundle.bytes().len() + 128).unwrap(),
            true,
            1_000,
        );
        let message = signed_inbound(REQUESTER, SERVICE, &wire);
        let mut provider = FixtureProvider::empty();
        provider.evidence.push_back(Ok(bundle));
        let frames = outbound(service.handle_inbound(&message, &mut provider, 10).unwrap());
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].frame_kind(),
            GatewayLxmfFrameKind::EvidenceManifest
        );
        assert_eq!(
            frames[1].frame_kind(),
            GatewayLxmfFrameKind::EvidenceResponse
        );
        assert!(
            frames
                .iter()
                .all(|frame| frame.destination_hash() == REQUESTER)
        );
        assert!(frames.iter().all(|frame| frame.source_hash() == SERVICE));
    }

    #[test]
    fn bulk_consensus_waits_for_exact_durable_approval_and_replays_are_rate_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let request_id = [0x6a; 16];
        let bundle = verified_builder().consensus_bundle().clone();
        assert!(bundle.bytes().len() > super::MAX_INBOUND_ATTACHMENT_BYTES);
        let wire = encode_test_evidence_request(
            request_id,
            MessagingEvidenceKind::Consensus,
            CHECKPOINT_ROOT,
            bundle.bytes().len() as u32,
            false,
            1_000,
        );
        let request = signed_inbound(REQUESTER, SERVICE, &wire);
        let manifest = {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = FixtureProvider::empty();
            provider.evidence.push_back(Ok(bundle));
            let frames = outbound(service.handle_inbound(&request, &mut provider, 10).unwrap());
            assert_eq!(frames.len(), 1);
            assert_eq!(
                frames[0].frame_kind(),
                GatewayLxmfFrameKind::EvidenceManifest
            );
            frames[0].attachment().to_vec()
        };

        let mut reopened = open(&path, [REQUESTER]);
        let mut no_provider = FixtureProvider::empty();
        let approval = bulk_approval(&manifest, 1_000);
        assert_eq!(
            reopened.handle_inbound(
                &signed_inbound(OTHER_REQUESTER, SERVICE, &approval),
                &mut no_provider,
                11,
            ),
            Err(GatewayLxmfServiceError::RequesterNotConfigured)
        );
        let mut wrong = bulk_approval(&manifest, 1_000);
        wrong[7 + 1 + 8 + 1 + 16 + 8 + 1] ^= 1;
        assert!(matches!(
            reopened.handle_inbound(
                &signed_inbound(REQUESTER, SERVICE, &wrong),
                &mut no_provider,
                11,
            ),
            Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::ReplayConflict
            ))
        ));
        let stale = bulk_approval(&manifest, 11);
        assert!(matches!(
            reopened.handle_inbound(
                &signed_inbound(REQUESTER, SERVICE, &stale),
                &mut no_provider,
                11,
            ),
            Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::Message(GatewayMessageError::Expired)
            ))
        ));

        let approved_message = signed_inbound(REQUESTER, SERVICE, &approval);
        for now in 12..=14 {
            let frames = outbound(
                reopened
                    .handle_inbound(&approved_message, &mut no_provider, now)
                    .unwrap(),
            );
            assert_eq!(frames.len(), 1);
            assert_eq!(
                frames[0].frame_kind(),
                GatewayLxmfFrameKind::EvidenceResponse
            );
            drop(reopened);
            reopened = open(&path, [REQUESTER]);
        }
        assert_eq!(
            reopened
                .handle_inbound(&approved_message, &mut no_provider, 15)
                .unwrap(),
            GatewayLxmfServiceOutcome::AcceptedNoOutput
        );
        assert!(no_provider.evidence.is_empty());
    }

    #[test]
    fn composite_receipt_bulk_release_preserves_checkpoint_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.sqlite");
        let request_id = [0x6b; 16];
        let bundle = verified_finalized_package();
        assert!(bundle.bytes().len() > super::MAX_INBOUND_ATTACHMENT_BYTES);
        let tx_hash = Verifier::sepolia()
            .parse_finalized_receipt_evidence(bundle.bytes())
            .unwrap()
            .finalized_receipt()
            .receipt_proof
            .tx_hash;
        let wire = encode_test_contextual_evidence_request(
            request_id,
            MessagingEvidenceKind::FinalizedReceiptPackage,
            tx_hash,
            343_888,
            CHECKPOINT_ROOT,
            bundle.bytes().len() as u32,
            false,
            1_000,
        );
        let manifest = {
            let mut service = open(&path, [REQUESTER]);
            let mut provider = FixtureProvider::empty();
            provider.evidence.push_back(Ok(bundle.clone()));
            let frames = outbound(
                service
                    .handle_inbound(
                        &signed_inbound(REQUESTER, SERVICE, &wire),
                        &mut provider,
                        10,
                    )
                    .unwrap(),
            );
            assert_eq!(frames.len(), 1);
            frames[0].attachment().to_vec()
        };

        let mut service = open(&path, [REQUESTER]);
        let mut provider = FixtureProvider::empty();
        let mut wrong_context = bulk_approval(&manifest, 1_000);
        let context_offset = 7 + 1 + 8 + 1 + 16 + 8 + 1;
        wrong_context[context_offset] ^= 1;
        assert!(matches!(
            service.handle_inbound(
                &signed_inbound(REQUESTER, SERVICE, &wrong_context),
                &mut provider,
                11,
            ),
            Err(GatewayLxmfServiceError::Admission(
                GatewayAdmissionError::ReplayConflict
            ))
        ));
        let approval = bulk_approval(&manifest, 1_000);
        let frames = outbound(
            service
                .handle_inbound(
                    &signed_inbound(REQUESTER, SERVICE, &approval),
                    &mut provider,
                    12,
                )
                .unwrap(),
        );
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].frame_kind(),
            GatewayLxmfFrameKind::EvidenceResponse
        );
        assert!(frames[0].attachment().ends_with(bundle.bytes()));
    }

    #[test]
    fn debug_output_redacts_identities_and_attachment_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let mut service = open(&directory.path().join("gateway.sqlite"), [REQUESTER]);
        let (message, raw, hash) = relay_message([0x5a; 16]);
        let mut provider = accepted_provider(hash);
        let outcome = service.handle_inbound(&message, &mut provider, 10).unwrap();
        let rendered = format!("{service:?} {outcome:?}");
        assert!(rendered.contains("attachment_len"));
        assert!(!rendered.contains(&alloy_primitives::hex::encode(REQUESTER)));
        assert!(!rendered.contains(&alloy_primitives::hex::encode(SERVICE)));
        assert!(!rendered.contains(&alloy_primitives::hex::encode(raw)));
    }
}
