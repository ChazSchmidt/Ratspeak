#!/usr/bin/env node
'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var dashboardRoot = path.join(__dirname, '..');
var source = fs.readFileSync(path.join(dashboardRoot, 'static/js/ethereum_wallet.js'), 'utf8');
var html = fs.readFileSync(path.join(dashboardRoot, 'index.html'), 'utf8');

function functionSource(name) {
    var start = source.indexOf('function ' + name + '(');
    assert.notStrictEqual(start, -1, name + ' must exist');
    var brace = source.indexOf('{', start);
    var depth = 0;
    for (var index = brace; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}') {
            depth--;
            if (depth === 0) return source.slice(start, index + 1);
        }
    }
    throw new Error('unterminated function ' + name);
}

var context = {
    BigInt: BigInt,
    Math: Math,
    Number: Number,
    String: String,
    RegExp: RegExp,
    Date: { now: function() { return 1800000010000; } },
    ETHEREUM_SEPOLIA_CHAIN_ID: 11155111,
    ETHEREUM_NATIVE_TRANSFER_GAS: 21000n
};
vm.createContext(context);
vm.runInContext([
    'var ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;',
    'var ETHEREUM_NATIVE_TRANSFER_GAS = 21000n;',
    functionSource('ethereumCanonicalDecimal'),
    functionSource('ethereumDecimalToBaseUnits'),
    functionSource('ethereumWeiToEth'),
    functionSource('ethereumNormalizeTransactionHash'),
    functionSource('ethereumNormalizeTransferIntent'),
    functionSource('ethereumDuration'),
    functionSource('ethereumAccountCheckPresentation'),
    functionSource('ethereumUpdateSetupDisclosure'),
    functionSource('ethereumServicePresentation'),
    functionSource('ethereumAccountPresentation'),
    functionSource('ethereumBlockNumber'),
    functionSource('ethereumBlockDistance'),
    functionSource('ethereumSelectedServicePresentation'),
    functionSource('ethereumTransactionStatusObservationPresentation'),
    functionSource('ethereumTransactionTimeline'),
    functionSource('ethereumTransactionPresentation'),
    functionSource('ethereumNativeUiState'),
    functionSource('ethereumEvidenceReviewUiState'),
    functionSource('ethereumCheckpointReviewUiState'),
    functionSource('ethereumCheckpointFileImportUiState')
].join('\n'), context, { filename: 'ethereum_wallet.js' });

var setupDisclosure = { open: true };
context.document = {
    getElementById: function(id) {
        return id === 'ethereum-setup' ? setupDisclosure : null;
    }
};
context.ethereumWalletUi = {
    setupDisclosureInitialized: false,
    setupComplete: false
};
context.ethereumUpdateSetupDisclosure(true);
assert.strictEqual(setupDisclosure.open, false,
    'completed setup starts collapsed');
setupDisclosure.open = true;
context.ethereumUpdateSetupDisclosure(true);
assert.strictEqual(setupDisclosure.open, true,
    'polling preserves a manual disclosure choice');
context.ethereumUpdateSetupDisclosure(false);
assert.strictEqual(setupDisclosure.open, true,
    'setup reopens when readiness is lost');
setupDisclosure.open = false;
context.ethereumUpdateSetupDisclosure(false);
assert.strictEqual(setupDisclosure.open, false,
    'incomplete setup may still be collapsed manually');
context.ethereumUpdateSetupDisclosure(true);
assert.strictEqual(setupDisclosure.open, false,
    'setup collapses when readiness is regained');

var valid = context.ethereumNormalizeTransferIntent({
    recipient: '0x1111111111111111111111111111111111111111',
    valueEth: '0.001',
    maxFeeGwei: '20',
    priorityFeeGwei: '1.5'
});
assert.deepStrictEqual(JSON.parse(JSON.stringify(valid.request)), {
    kind: 'transfer',
    recipient: '0x1111111111111111111111111111111111111111',
    value_wei: '1000000000000000',
    max_fee_per_gas_wei: '20000000000',
    max_priority_fee_per_gas_wei: '1500000000'
});
assert.strictEqual(valid.amountDisplay, '0.001 ETH');
assert.strictEqual(valid.feeDisplay, '0.00042 ETH');
assert.strictEqual(valid.totalDisplay, '0.00142 ETH');
assert.strictEqual(context.ethereumNormalizeTransactionHash('ab'.repeat(32)), '0x' + 'ab'.repeat(32));
assert.strictEqual(context.ethereumNormalizeTransactionHash('0x' + 'AB'.repeat(32)), '0x' + 'ab'.repeat(32));
assert.strictEqual(context.ethereumNormalizeTransactionHash('0x12'), null);

var waitingCheck = context.ethereumAccountCheckPresentation({
    stage: 'waiting_for_gateway',
    created_at_unix: 1800000000,
    expires_at_unix: 1800007200
});
assert.strictEqual(waitingCheck.label, 'Waiting for service');
assert.strictEqual(waitingCheck.active, true);
assert(waitingCheck.message.includes("handed to Ratspeak's outbound queue"));
assert(!waitingCheck.message.includes('delivered'));
var retryableWaitingCheck = context.ethereumAccountCheckPresentation({
    stage: 'waiting_for_gateway',
    created_at_unix: Math.floor(Date.now() / 1000) - 121,
    expires_at_unix: Math.floor(Date.now() / 1000) + 7000
});
assert.strictEqual(retryableWaitingCheck.retry, true);
assert(retryableWaitingCheck.message.includes('retry the same bounded request'));
var missingServiceContact = context.ethereumAccountCheckPresentation({
    stage: 'service_contact_required',
    created_at_unix: 1800000000,
    expires_at_unix: 1800007200
});
assert.strictEqual(missingServiceContact.label, 'Account check paused');
assert(missingServiceContact.message.includes('Ratspeak contact card'));
assert.strictEqual(missingServiceContact.active, true);
assert.strictEqual(context.ethereumAccountCheckPresentation({
    stage: 'failed', created_at_unix: 1800000000, expires_at_unix: 1800007200
}).active, false);
assert.strictEqual(context.ethereumServicePresentation({}).label, 'No service selected');
assert(context.ethereumServicePresentation({ public_service_contact_added: true })
    .message.includes('public test service is in Ratspeak Contacts'));
assert.strictEqual(context.ethereumServicePresentation({
    gateway_selected: true,
    gateway_contact_ready: false
}).label, 'Service selected · Contact needed');
assert.strictEqual(context.ethereumServicePresentation({
    gateway_selected: true,
    gateway_contact_ready: true,
    account_check: { stage: 'waiting_for_gateway' }
}).label, 'Waiting for RPC response');
var reachableService = context.ethereumServicePresentation({
    gateway_selected: true,
    gateway_contact_ready: true,
    selected_service: {
        display_name: 'Ratspeak Sepolia Service',
        destination_fingerprint: '1111…1111',
        avatar_seed: '1'.repeat(32)
    },
    account_check: { stage: 'verifying' }
});
assert.strictEqual(reachableService.label, 'Reachable');
assert(reachableService.message.includes('Ratspeak Sepolia Service returned an RPC response'));
assert(!reachableService.message.includes('authenticated'));
assert(!context.ethereumServicePresentation({
    gateway_selected: true,
    gateway_contact_ready: true
}).message.includes('connected'));

[
    { recipient: 'not-an-address', valueEth: '1', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: '0x0000000000000000000000000000000000000000', valueEth: '1', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: valid.request.recipient, valueEth: '0', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: valid.request.recipient, valueEth: '01', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: valid.request.recipient, valueEth: '1e-3', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: valid.request.recipient, valueEth: '0.0000000000000000001', maxFeeGwei: '2', priorityFeeGwei: '1' },
    { recipient: valid.request.recipient, valueEth: '1', maxFeeGwei: '0', priorityFeeGwei: '0' },
    { recipient: valid.request.recipient, valueEth: '1', maxFeeGwei: '1', priorityFeeGwei: '2' },
    { recipient: valid.request.recipient, valueEth: '1' + '0'.repeat(80), maxFeeGwei: '1', priorityFeeGwei: '0' }
].forEach(function(fields) {
    assert.strictEqual(typeof context.ethereumNormalizeTransferIntent(fields).error, 'string');
});

var unknown = context.ethereumAccountPresentation(null);
var staleZero = context.ethereumAccountPresentation({
    address: valid.request.recipient,
    assurance: 'stale',
    balance_display: '0',
    nonce_display: '0',
    evidence_age_seconds: 90
});
var staleNonzero = context.ethereumAccountPresentation({
    address: valid.request.recipient,
    assurance: 'stale',
    balance_display: '10',
    nonce_display: '2',
    evidence_age_seconds: 90
});
var currentZero = context.ethereumAccountPresentation({
    address: valid.request.recipient,
    assurance: 'current_verified',
    balance_display: '0',
    nonce_display: '0',
    evidence_age_seconds: 3
});
var currentNonzero = context.ethereumAccountPresentation({
    address: valid.request.recipient,
    assurance: 'current_verified',
    balance_display: '1000000000000000001',
    nonce_display: '4',
    evidence_age_seconds: 3
});
assert.strictEqual(unknown.balance, '...');
assert.strictEqual(staleZero.balance, '...');
assert.strictEqual(staleNonzero.balance, '...');
assert.strictEqual(currentZero.balance, '0 ETH',
    'zero is shown only for the node chain-time-current exact-proof state');
assert.strictEqual(currentNonzero.balance, '1.000000000000000001 ETH');
assert.strictEqual(currentNonzero.nonce, '4');

var assuranceCases = {
    unknown: 'No exact verified receipt available',
    receipt_needs_reverification: 'Receipt evidence needs reverification',
    verified_success: 'Verified finalized success',
    verified_failure: 'Verified finalized failure'
};
Object.keys(assuranceCases).forEach(function(state) {
    var rendered = context.ethereumTransactionPresentation({
        tx_hash: '0x' + 'ab'.repeat(32),
        assurance: state
    });
    assert.strictEqual(rendered.assurance, assuranceCases[state]);
    assert.strictEqual(rendered.verified,
        state === 'verified_success' || state === 'verified_failure');
});
[
    ['signed_locally', 'Signed locally — not sent'],
    ['transport_delivered', 'Delivered to service — not confirmed'],
    ['gateway_acknowledged', 'Service acknowledged — not confirmed'],
    ['rpc_accepted', 'RPC accepted — awaiting finality']
].forEach(function(testCase) {
    var rendered = context.ethereumTransactionPresentation({
        tx_hash: '0x' + 'ab'.repeat(32),
        assurance: 'signed_unconfirmed',
        progress: testCase[0]
    });
    assert.strictEqual(rendered.assurance, testCase[1]);
    assert.strictEqual(rendered.verified, false);
});
['relayed', 'rpc_success', 'account_changed', 'gateway_acknowledged'].forEach(function(state) {
    var rendered = context.ethereumTransactionPresentation({
        tx_hash: '0x' + 'ab'.repeat(32),
        assurance: state
    });
    assert.strictEqual(rendered.assurance, 'No exact verified receipt available');
    assert.strictEqual(rendered.verified, false);
});

var includedObservation = {
    status: 'included',
    included_block: { number: 1000, hash: '0x' + '10'.repeat(32) },
    heads: {
        latest: { number: 1010, hash: '0x' + '11'.repeat(32) },
        safe: { number: 1008, hash: '0x' + '12'.repeat(32) },
        finalized: { number: 990, hash: '0x' + '13'.repeat(32) }
    },
    observed_at_unix: 1800000000,
    source_hash: 'ab'.repeat(16),
    authority: 'rpc_status',
    continuity: 'observed',
    previous_inclusion: null
};
var reportedIncluded = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: includedObservation
});
assert.strictEqual(reportedIncluded.assurance, 'Included in a block — verifying');
assert.strictEqual(reportedIncluded.verified, false);
assert.strictEqual(reportedIncluded.observation.included.number, 1000);
assert(reportedIncluded.timeline.some(function(stage) {
    return stage.label === 'RPC sees transaction in block 1,000' &&
        stage.authority === 'RPC status from your selected Ethereum service';
}));
assert(reportedIncluded.timeline.some(function(stage) {
    return stage.label === 'Network confirmation progress' &&
        stage.detail.includes('10 blocks past the inclusion block') &&
        stage.detail.includes('10 blocks behind the inclusion block');
}));
assert(!reportedIncluded.timeline.map(function(stage) {
    return stage.label + ' ' + stage.detail;
}).join(' ').includes('%'));
assert(!reportedIncluded.timeline.map(function(stage) {
    return stage.label + ' ' + stage.detail + ' ' + stage.authority;
}).join(' ').toLowerCase().includes('authenticated'),
    'prominent timeline copy must not visually overweight authentication');
assert(!reportedIncluded.timeline.map(function(stage) {
    return stage.label + ' ' + stage.detail + ' ' + stage.authority;
}).join(' ').toLowerCase().includes('report'),
    'wallet-facing timeline copy should use familiar transaction status language');

var receiptRequested = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: Object.assign({}, includedObservation, {
        heads: Object.assign({}, includedObservation.heads, {
            finalized: { number: 1005, hash: '0x' + '14'.repeat(32) }
        })
    }),
    receipt_request: {
        state: 'requested',
        created_at_unix: 1800000001,
        expires_at_unix: 1800007201
    }
});
assert(receiptRequested.timeline.some(function(stage) {
    return stage.label === 'Receipt proof requested' &&
        stage.detail.includes('your selected Ethereum service');
}), 'a scheduled proof request must replace generic receipt waiting copy');

var pendingTimeline = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: Object.assign({}, includedObservation, {
        status: 'pending',
        included_block: null
    }),
    receipt_request: {
        state: 'requested',
        created_at_unix: 1800000001,
        expires_at_unix: 1800007201
    }
});
assert(!pendingTimeline.timeline.some(function(stage) {
    return stage.label === 'Network confirmation progress';
}), 'chain-head trivia must stay out of the timeline until inclusion');
assert(!pendingTimeline.timeline.some(function(stage) {
    return stage.label === 'Receipt proof requested';
}), 'premature receipt work must not look like meaningful progress before inclusion');

var namedService = {
    display_name: 'Sepolia Relay North',
    destination_fingerprint: 'abab…abab',
    avatar_seed: 'ab'.repeat(16)
};
var namedReportedIncluded = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: includedObservation
}, namedService);
assert(namedReportedIncluded.timeline.some(function(stage) {
    return stage.authority === 'RPC status from Sepolia Relay North';
}), 'valid projected Contact names should identify the RPC source prominently');
assert.strictEqual(namedReportedIncluded.timeline.filter(function(stage) {
    return stage.sourceContact && stage.sourceContact.avatarSeed === 'ab'.repeat(16);
}).length, 4, 'matched Contacts should appear in the service and RPC timeline rows');
assert.strictEqual(namedReportedIncluded.selectedService.destinationFingerprint, 'abab…abab');
assert.strictEqual(namedReportedIncluded.selectedService.avatarSeed,
    'ab'.repeat(16));
assert.strictEqual(context.ethereumSelectedServicePresentation({
    display_name: 'Invented',
    destination_fingerprint: '60c6…791a',
    avatar_seed: 'not-a-contact-destination'
}), null, 'invalid service identity projections must fall back rather than render');
assert.strictEqual(context.ethereumSelectedServicePresentation({
    display_name: 'Legacy service',
    destination_fingerprint: '60c6…791a'
}), null, 'missing avatar seeds must retain the generic service fallback');

var changedService = {
    display_name: 'Replacement Relay',
    destination_fingerprint: 'cdcd…cdcd',
    avatar_seed: 'cd'.repeat(16)
};
var changedServiceReport = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: includedObservation
}, changedService);
assert.strictEqual(changedServiceReport.selectedService, null,
    'a current Contact must not be attached to an older service observation');
assert(changedServiceReport.timeline.some(function(stage) {
    return stage.authority === 'RPC status from the Ethereum service that returned this status';
}));
assert(!changedServiceReport.timeline.map(function(stage) {
    return stage.label + ' ' + stage.detail + ' ' + stage.authority;
}).join(' ').includes('Replacement Relay'));
assert(!changedServiceReport.timeline.some(function(stage) {
    return stage.sourceContact;
}), 'mismatched service observations must never render the current Contact avatar');

var notSeenObservation = Object.assign({}, includedObservation, {
    status: 'not_seen',
    included_block: null
});
var notSeen = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'gateway_acknowledged',
    status_observation: notSeenObservation
});
assert.strictEqual(notSeen.assurance, 'Not currently visible to this service');
assert(!notSeen.note.toLowerCase().includes('failed'));

var awaitingReinclusionObservation = Object.assign({}, notSeenObservation, {
    continuity: 'awaiting_reinclusion',
    previous_inclusion: {
        number: 999,
        hash: '0x' + '14'.repeat(32),
        observed_at_unix: 1799999900
    }
});
var awaitingReinclusion = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'signed_unconfirmed',
    progress: 'rpc_accepted',
    status_observation: awaitingReinclusionObservation
});
assert.strictEqual(awaitingReinclusion.assurance, 'Awaiting reinclusion — not failed');
assert(awaitingReinclusion.timeline.some(function(stage) {
    return stage.label === 'Awaiting reinclusion' && stage.state === 'warning';
}));

var malformedObservation = Object.assign({}, includedObservation, {
    heads: Object.assign({}, includedObservation.heads, {
        safe: { number: 1011, hash: includedObservation.heads.safe.hash }
    })
});
assert.strictEqual(context.ethereumTransactionStatusObservationPresentation(malformedObservation), null,
    'unordered service-reported heads must not render');
assert.strictEqual(context.ethereumTransactionStatusObservationPresentation(Object.assign({},
    awaitingReinclusionObservation, { previous_inclusion: null })), null,
    'reorg copy requires durable prior inclusion evidence');

var locallyVerified = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'verified_success',
    progress: 'rpc_accepted',
    status_observation: includedObservation
});
assert.strictEqual(locallyVerified.assurance, 'Verified finalized success');
assert.strictEqual(locallyVerified.timeline[6].label, 'Confirmed');
assert.strictEqual(locallyVerified.timeline[6].authority,
    'Receipt proof verified on this device');
var locallyVerifiedWithoutServiceReport = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ab'.repeat(32),
    assurance: 'verified_success',
    progress: 'finalized',
    status_observation: null
});
assert.strictEqual(locallyVerifiedWithoutServiceReport.timeline[3].label,
    'Included in verified finalized receipt');
assert.strictEqual(locallyVerifiedWithoutServiceReport.timeline[3].authority,
    'Receipt proof verified on this device');
assert(!locallyVerifiedWithoutServiceReport.timeline.some(function(stage) {
    return stage.label === 'Awaiting RPC status';
}), 'a verified receipt must not retain an already-superseded waiting step');
assert(!locallyVerifiedWithoutServiceReport.timeline.some(function(stage) {
    return stage.label === 'RPC accepted';
}), 'local receipt verification must not invent RPC acceptance');
assert.strictEqual(locallyVerifiedWithoutServiceReport.timeline[4].label, 'Confirmed');

var locallyVerifiedFailureWithoutServiceReport = context.ethereumTransactionPresentation({
    tx_hash: '0x' + 'ac'.repeat(32),
    assurance: 'verified_failure',
    progress: 'finalized',
    status_observation: null
});
assert(!locallyVerifiedFailureWithoutServiceReport.timeline.some(function(stage) {
    return stage.label === 'Awaiting RPC status' || stage.label === 'RPC accepted';
}), 'verified failure must also omit a missing optional RPC-status step');
assert.strictEqual(locallyVerifiedFailureWithoutServiceReport.timeline[4].label, 'Failed');

var admittedAndroid = context.ethereumNativeUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'android',
    native_authorization: 'available'
});
assert.strictEqual(admittedAndroid.enabled, true);
assert(admittedAndroid.message.includes('check biometric and hardware-backed protection'));
var admittedLinux = context.ethereumNativeUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'available'
});
assert.strictEqual(admittedLinux.enabled, true);
assert(admittedLinux.message.includes('native dialogs'));
var uncheckedLinux = context.ethereumNativeUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'checking'
});
assert.strictEqual(uncheckedLinux.enabled, true,
    'Linux setup must remain reachable before the Secret Service probe runs');
assert.strictEqual(uncheckedLinux.setupRequired, true);
assert(uncheckedLinux.message.includes('Create a wallet or import one'));
assert(uncheckedLinux.message.includes('Secret Recovery Phrase'));
assert.strictEqual(context.ethereumNativeUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'android',
    native_authorization: 'checking'
}).enabled, false, 'Android checking must not bypass its native readiness gate');
['ios', 'unsupported'].forEach(function(platform) {
    assert.strictEqual(context.ethereumNativeUiState({
        chain_id: 11155111,
        network: 'sepolia',
        mainnet_available: false,
        platform: platform,
        native_authorization: 'unavailable'
    }).enabled, false);
    assert.strictEqual(context.ethereumEvidenceReviewUiState({
        chain_id: 11155111,
        network: 'sepolia',
        mainnet_available: false,
        platform: platform,
        native_authorization: 'unavailable',
        native_bulk_evidence_review: 'available'
    }).enabled, false, 'unsupported platforms must remain disabled even with a bad capability value');
});
assert.strictEqual(context.ethereumNativeUiState({
    chain_id: 1,
    network: 'mainnet',
    mainnet_available: true,
    platform: 'android',
    native_authorization: 'available'
}).enabled, false);

var linuxReviewWithoutCustody = context.ethereumEvidenceReviewUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'unavailable',
    native_bulk_evidence_review: 'available'
});
assert.strictEqual(linuxReviewWithoutCustody.enabled, true,
    'bulk evidence review must not depend on wallet custody');
var linuxCheckpointWithoutCustody = context.ethereumCheckpointReviewUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'unavailable',
    native_checkpoint_review: 'available'
});
assert.strictEqual(linuxCheckpointWithoutCustody.enabled, true,
    'manual checkpoint review must not depend on wallet custody or gateway configuration');
assert.strictEqual(context.ethereumCheckpointFileImportUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'unavailable',
    native_checkpoint_file_import: 'available'
}).enabled, true, 'manual file acquisition must not depend on wallet custody or gateway configuration');
assert.strictEqual(context.ethereumNativeUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'unavailable'
}).enabled, false, 'wallet management remains custody-gated');
['ios', 'unsupported'].forEach(function(platform) {
    assert.strictEqual(context.ethereumEvidenceReviewUiState({
        chain_id: 11155111,
        network: 'sepolia',
        mainnet_available: false,
        platform: platform,
        native_authorization: 'unavailable',
        native_bulk_evidence_review: 'unavailable'
    }).enabled, false);
});
assert.strictEqual(context.ethereumEvidenceReviewUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'android',
    native_authorization: 'available',
    native_bulk_evidence_review: 'unavailable'
}).enabled, false, 'Android remains disabled until its native review adapter is installed');
assert.strictEqual(context.ethereumEvidenceReviewUiState({
    chain_id: 11155111,
    network: 'sepolia',
    mainnet_available: false,
    platform: 'linux',
    native_authorization: 'unavailable',
    native_bulk_evidence_review: 'unavailable'
}).enabled, false, 'an unavailable Linux adapter must not be advertised');

var commandValues = Array.from(source.matchAll(/:\s*'(ethereum_[a-z_]+)'/g), function(match) {
    return match[1];
}).sort();
assert.deepStrictEqual(commandValues, [
    'ethereum_add_public_service_contact',
    'ethereum_connect_sepolia',
    'ethereum_feature_status',
    'ethereum_import_checkpoint_file',
    'ethereum_import_gateway_card',
    'ethereum_latest_transaction',
    'ethereum_launch_native_wallet',
    'ethereum_public_account',
    'ethereum_review_pending_bulk_evidence',
    'ethereum_review_pending_checkpoint',
    'ethereum_review_pending_gateway_card',
    'ethereum_setup_status',
    'ethereum_synchronize',
    'ethereum_transaction_assurance',
    'ethereum_transfer_review',
    'ethereum_update_transaction_status'
]);
assert(!/RS\.invoke\(\s*['"]ethereum_/.test(source),
    'Ethereum calls must remain on the explicit command registry');

var ethereumHtml = html.slice(
    html.indexOf('<div class="view" id="view-ethereum">'),
    html.indexOf('<div class="view" id="view-settings">')
);
var inputNames = Array.from(ethereumHtml.matchAll(/<(?:input|textarea)[^>]+?id="([^"]+)"/g),
    function(match) { return match[1]; });
assert.deepStrictEqual(inputNames, [
    'ethereum-recipient',
    'ethereum-value-eth',
    'ethereum-max-fee-gwei',
    'ethereum-priority-fee-gwei'
]);
assert(!/(mnemonic|seed|private.key|passphrase|calldata|provider.url|gateway|raw.sign|unlock|export)/i
    .test(inputNames.join(' ')), 'the WebView must not expose secret, signing, RPC, or gateway fields');
assert(ethereumHtml.includes('Experimental, unaudited'));
assert(ethereumHtml.includes('only after it verifies the exact finalized receipt itself'));
assert(ethereumHtml.includes('id="ethereum-balance" aria-live="polite">...</div>'));
assert(html.includes('ethereum-feature-entry hidden'), 'feature navigation starts hidden');
assert(source.includes("currentView !== 'ethereum'"),
    'durable transaction polling must stop when the feature view is not active');
assert(source.includes('ethereumLoadLatestTransaction().finally(ethereumScheduleTransactionPoll)'),
    'the active feature view must refresh durable signed-transaction state');
assert(source.includes('var account = setup && setup.account'));
assert(!source.includes('RS.invoke(ETHEREUM_UI_COMMANDS.account)'),
    'setup and account state must come from one identity-fenced native snapshot');
assert(!source.includes('result.transaction_hash'),
    'asynchronous native signing must not depend on the launcher response carrying a hash');
assert(ethereumHtml.includes('id="ethereum-sync-btn" type="button" disabled>Check my account</button>'));
assert(ethereumHtml.includes('id="ethereum-account-check-created-local"'));
assert(ethereumHtml.includes('id="ethereum-account-check-created-unix"'));
assert(ethereumHtml.includes('id="ethereum-account-check-expires-local"'));
assert(ethereumHtml.includes('id="ethereum-account-check-expires-unix"'));
assert(ethereumHtml.includes('id="ethereum-refresh-btn" type="button">Refresh</button>'));
assert(ethereumHtml.includes('id="ethereum-transaction-timeline" aria-label="Transaction progress"'));
assert(ethereumHtml.includes('id="ethereum-transaction-technical"'));
assert(ethereumHtml.includes('id="ethereum-update-transaction-status-btn" type="button">Update status</button>'));
assert(ethereumHtml.includes('id="ethereum-setup-service-avatar" aria-hidden="true"'));
assert(ethereumHtml.includes('id="ethereum-transaction-service-avatar" aria-hidden="true"'),
    'the correlated RPC source Contact should remain visible above the timeline');
assert(ethereumHtml.includes('Set up Ethereum'));
assert(ethereumHtml.includes('<details class="panel ethereum-setup" id="ethereum-setup" open>'));
assert(ethereumHtml.includes('<summary class="panel-header ethereum-setup-header">'));
assert(source.includes('ethereumUpdateSetupDisclosure('),
    'setup readiness must drive the disclosure default');
assert(ethereumHtml.includes('Create or import a wallet'));
assert(source.includes("setup.wallet_configured === true ? 'Wallet settings' : 'Create or import wallet'"));
assert(source.includes('then choose Create wallet or Import wallet in the secure system window'));
assert(ethereumHtml.includes('Bootstrap network checkpoint'));
assert(ethereumHtml.includes('Bootstrap Sepolia checkpoint'));
assert(!ethereumHtml.includes('Connect to Sepolia'));
assert(ethereumHtml.includes('Add public test service to Contacts'));
assert(ethereumHtml.includes('Choose Ethereum service'));
assert(ethereumHtml.includes('Manage Ratspeak Contacts'));
assert(ethereumHtml.includes('id="ethereum-change-checkpoint-btn"'));
assert(ethereumHtml.includes('>Change checkpoint</button>'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-details"'));
assert(ethereumHtml.includes('<summary>Verification details</summary>'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-epoch"'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-root"'));
assert(ethereumHtml.includes('id="ethereum-copy-checkpoint-root-btn"'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-sources"'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-bootstrap-source"'));
assert(ethereumHtml.includes('id="ethereum-checkpoint-bootstrap-link"'));
assert(source.includes('function ethereumRenderCheckpointDetails(checkpoint)'));
assert(source.includes('checkpoint.local_bootstrap_verified === true'));
assert(source.includes("checkpoint.approval_basis === 'provider_agreement'"));
assert(source.includes('checkpoint.known_online_provider_agreement === true'));
assert(source.includes('separately acquired light-client bootstrap data'));
assert(source.includes('approved checkpoint card’s light-client bootstrap data'));
assert(source.includes('ethereum-sepolia-beacon-api.publicnode.com/eth/v1/beacon/light_client/bootstrap/'));
assert(source.includes("link.rel = 'noopener noreferrer'"));
assert(source.includes("ethereum-copy-checkpoint-root-btn"));
assert(!/<input[^>]+ethereum-checkpoint-root/.test(ethereumHtml),
    'checkpoint root must remain read-only and never be an authority input');
assert(ethereumHtml.includes('<summary>Advanced</summary>'));
assert(ethereumHtml.includes('Check your account'));
assert(ethereumHtml.includes('Sepolia testnet — test ETH only.'));
assert(ethereumHtml.includes('Do not import a wallet that holds real funds.'));
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.synchronize\)/g) || []).length, 1,
    'finite synchronization must have one explicit no-argument invocation');
assert(source.includes("loadEthereumWalletView({ preserveVisibleState: true })"),
    'same-profile polling and refresh must not blank the setup surface');
assert(source.includes('preserveVisibleState && ethereumWalletUi.setupStatus'),
    'a transient setup refresh failure must preserve the last confirmed setup');
assert(source.includes('Your saved wallet, checkpoint, and service have not been erased'));
assert(source.includes('Status will be checked again automatically'));
assert(source.includes('ethereumScheduleAccountCheckPoll(true)'),
    'a transient setup-status failure must schedule its own recovery');
assert(source.includes("ethereumWalletUi.setupRefreshFailed ? 'Status unavailable'"));
assert(!source.includes('!featureReady || ethereumWalletUi.setupRefreshFailed || ethereumWalletUi.synchronizing'),
    'a transient display refresh failure must not globally disable a backend-validated retry');
assert(source.includes('setup.wallet_configured !== true'),
    'account checking must remain disabled until a wallet address exists');
assert(!/ETHEREUM_UI_COMMANDS\.synchronize\s*,\s*\{/.test(source),
    'the WebView must not supply synchronization authority or request fields');
assert(source.includes('Looking for the selected Ethereum service on Reticulum'));
assert(source.includes("ethereumShowContextualAction('ethereum-sync-btn'"),
    'account-check action must stay hidden until the preceding setup steps are ready');
assert(source.includes('could not find a Reticulum route'));
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.reviewPendingEvidence\)/g) || []).length, 1,
    'bulk evidence review must have one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.reviewPendingEvidence\s*,\s*\{/.test(source),
    'the WebView must not supply bulk review snapshots or decisions');
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.reviewPendingCheckpoint\)/g) || []).length, 1,
    'checkpoint review must have one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.reviewPendingCheckpoint\s*,\s*\{/.test(source),
    'the WebView must not supply checkpoint roots, bundles, provenance, or decisions');
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.importCheckpointFile\)/g) || []).length, 1,
    'checkpoint file import must have one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.importCheckpointFile\s*,\s*\{/.test(source),
    'the WebView must not supply checkpoint file paths, URIs, bytes, or authority');
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.connectSepolia\)/g) || []).length, 1,
    'online checkpoint acquisition must have one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.connectSepolia\s*,\s*\{/.test(source),
    'the WebView must not supply checkpoint sources, URLs, roots, or proof bytes');
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.addPublicServiceContact\)/g) || []).length, 1,
    'public service bootstrap must have one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.addPublicServiceContact\s*,\s*\{/.test(source),
    'the WebView must not supply the curated service identity or contact card');
assert(!source.includes('result.pending'),
    'the native response must not claim pending state from a pre-modal snapshot');
assert(source.includes('result.launched === true'),
    'asynchronous native review launch must not be reported as a completed decision');
assert(ethereumHtml.includes('id="ethereum-review-pending-evidence-btn" type="button" disabled>Review download details</button>'));
assert(source.includes("RS.listen('ethereum_bulk_evidence_review_ready'"),
    'authenticated bulk manifests should open their native review automatically while this view is active');
assert(ethereumHtml.includes('id="ethereum-review-pending-checkpoint-btn" type="button" disabled>Review checkpoint</button>'));
assert(ethereumHtml.includes('id="ethereum-import-checkpoint-file-btn" type="button" disabled>Choose checkpoint file</button>'));
assert(source.includes("classList.toggle('hidden', !visible)"),
    'review actions must only appear when setup state reports actionable work');
assert(source.includes('return ethereumReviewPendingCheckpoint()') &&
    source.includes('return ethereumReviewPendingGatewayCard()'),
    'validated native imports should continue directly into secure review');
assert(source.includes("getElementById('ethereum-import-gateway-card-btn').disabled = true"),
    'feature-status failure must disable native gateway import');
assert(source.includes("getElementById('ethereum-review-gateway-card-btn').disabled = true"),
    'feature-status failure must disable native gateway review');
assert(source.includes("status.native_gateway_pairing === 'contacts'") &&
    source.includes("status.native_gateway_pairing === 'file'"),
    'gateway pairing controls require an explicit native Contacts or file capability');
assert(!source.includes("gatewayPairingAvailable = featureReady && status.platform === 'linux'"),
    'the operating-system label alone must not enable native gateway pairing');
assert(source.includes("result.state !== 'queued' && result.state !== 'active'"),
    'finite synchronization must distinguish newly queued from resumed active work');
assert(source.includes('Account checking is already in progress. Pending requests were resumed.'),
    'resumed synchronization must not claim terminal rows were newly queued');
assert(source.includes('ethereumWalletUi.syncFeedbackError') &&
    source.includes('ethereumWalletUi.syncFeedback ||'),
    'the current invocation error must not be hidden by older account progress');
assert(source.includes("gatewaySelected ? 'Change service' : 'Choose Ethereum service'"),
    'a selected service must expose an understandable replacement action');
assert(source.includes("ethereumShowContextualAction('ethereum-add-public-service-btn'"),
    'a configured public test service must bootstrap through ordinary Contacts');
assert(source.includes('setup.public_service_contact_added !== true'),
    'the public-service bootstrap must stop offering Add after durable Contact import');
assert(source.includes("ethereumShowContextualAction('ethereum-open-contacts-btn'"),
    'the user must always have a direct route to manage service Contacts');
assert(source.includes('gateway_contact_ready') && source.includes('Contact needed'),
    'a selected service must not be called ready without a matching Ratspeak Contact');
assert(source.includes("checkpointReady ? 'Import replacement checkpoint file'"),
    'an installed checkpoint must expose its bounded replacement path');
assert(source.includes('ethereumStartNativeSetupPolling()'),
    'asynchronous Android setup and picker callbacks need bounded status polling');
assert(source.includes("loadEthereumWalletView({ preserveVisibleState: true }).then(function()"),
    'transfer preparation must refresh the verified account state immediately before native review');
assert(source.includes('ethereum_transfer_requires_current_proof') &&
    source.includes('too old to prepare this transfer safely'),
    'stale account proofs must produce precise transfer guidance');
assert(source.includes('last verified balance remains shown'),
    'a failed transfer refresh must preserve the last verified balance in the UI');
assert(source.includes("ethereumWalletUi.featureStatus.platform === 'android'"),
    'asynchronous Android launch must not be reported as completed signing');
assert(source.includes('ethereum_native_signing_result_invalid'),
    'synchronous native completion must return its exact operation correlation');
assert(source.includes('ethereum_signed_transaction_correlation_failed') &&
    source.includes('transaction.tx_hash) !== signedTxHash'),
    'automatic relay must be bound to the exact transaction returned by native signing');
assert(source.includes('return ethereumSynchronize({ propagateError: true });'),
    'users must not need to press account refresh after signing');
assert(source.includes('if (propagateError) throw error;'),
    'automatic delivery scheduling errors must return to the signed-state handler');
assert(source.includes('Signed locally, but Ratspeak could not schedule delivery yet.'),
    'relay scheduling failure must not be mislabeled as a signing failure');
assert(source.includes('The wallet password is incorrect. Nothing was signed or sent; try again.'),
    'native password failure must be actionable without exposing secret input');
assert(source.includes('Transaction signing was cancelled. Nothing was signed or sent.'),
    'native cancellation must not be presented as an unknown preparation failure');
assert(source.includes('ethereumSetNativeCeremonyActive(true)') &&
    source.includes('ethereumScheduleAccountCheckPoll(false)'),
    'secret-bearing native signing must suspend WebView status polling');
assert(source.includes('clearTimeout(ethereumWalletUi.transactionPollTimer)'),
    'native signing must stop transaction polling that could starve GTK input');
assert(source.includes('if (!ethereumWalletUi.latestTransactionLoaded) ethereumRenderTransaction(null);'),
    'polling failures must preserve the last durable transaction view');
assert.strictEqual((source.match(/RS\.invoke\(ETHEREUM_UI_COMMANDS\.updateTransactionStatus\)/g) || []).length, 1,
    'transaction status has one explicit no-argument invocation');
assert(!/ETHEREUM_UI_COMMANDS\.updateTransactionStatus\s*,\s*\{/.test(source),
    'the WebView must not choose a transaction hash or status destination');
assert(source.includes("addEventListener('click', ethereumUpdateTransactionStatus)"),
    'status requests must be a contextual user action, not part of local polling');
assert(source.includes('Ratspeak verified the sender’s identity. This RPC status is not an Ethereum proof.'),
    'RPC sender verification belongs in technical details and must not imply Ethereum proof');
assert(!source.includes('Connected RPC'),
    'transaction copy must not imply persistent RPC reachability');
assert(source.includes('identityAvatar(selectedService.avatarSeed, 40)'),
    'selected Ethereum services must reuse the global Ratspeak Contact avatar renderer');
assert(source.includes('identityAvatar(item.sourceContact.avatarSeed, 24)'),
    'matched RPC timeline sources must use the same global Contact avatar renderer');
assert(source.includes('if (!container || !avatar || !name) return;'),
    'optional Contact identity surfaces must be safe when their DOM nodes are absent');
assert(!source.includes('finality percentage') && !source.includes('estimated confirmation'),
    'service reports must not create a finality percentage or countdown');

console.log('Ethereum wallet UI tests passed');
