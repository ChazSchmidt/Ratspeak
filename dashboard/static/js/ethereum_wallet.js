// Experimental Ethereum surface. The WebView handles public display and plain
// transfer intent only; custody, exact review, authorization, and signing stay
// in the native wallet ceremony.

var ETHEREUM_UI_COMMANDS = Object.freeze({
    feature: 'ethereum_feature_status',
    setup: 'ethereum_setup_status',
    connectSepolia: 'ethereum_connect_sepolia',
    importCheckpointFile: 'ethereum_import_checkpoint_file',
    addPublicServiceContact: 'ethereum_add_public_service_contact',
    importGatewayCard: 'ethereum_import_gateway_card',
    account: 'ethereum_public_account',
    synchronize: 'ethereum_synchronize',
    latestTransaction: 'ethereum_latest_transaction',
    updateTransactionStatus: 'ethereum_update_transaction_status',
    launch: 'ethereum_launch_native_wallet',
    reviewPendingEvidence: 'ethereum_review_pending_bulk_evidence',
    reviewPendingCheckpoint: 'ethereum_review_pending_checkpoint',
    reviewPendingGatewayCard: 'ethereum_review_pending_gateway_card',
    review: 'ethereum_transfer_review',
    assurance: 'ethereum_transaction_assurance'
});
var ETHEREUM_SEPOLIA_CHAIN_ID = 11155111;
var ETHEREUM_NATIVE_TRANSFER_GAS = 21000n;
var ethereumWalletUi = {
    featureStatus: null,
    setupStatus: null,
    account: null,
    latestTransaction: null,
    latestTransactionLoaded: false,
    updatingTransactionStatus: false,
    transactionStatusFeedback: '',
    refreshSequence: 0,
    transactionPollTimer: null,
    nativeSetupPollTimer: null,
    nativeSetupPollDeadline: 0,
    accountCheckPollTimer: null,
    nativeCeremonyActive: false,
    synchronizing: false,
    connectingSepolia: false,
    addingPublicService: false,
    reviewingEvidence: false,
    syncFeedback: null,
    syncFeedbackError: false,
    checkpointFeedback: null,
    checkpointFeedbackError: false,
    gatewayFeedback: null,
    gatewayFeedbackError: false,
    setupRefreshFailed: false,
    setupDisclosureInitialized: false,
    setupComplete: false,
    bound: false
};

function ethereumSetStep(stepName, state, label, message) {
    var step = document.getElementById('ethereum-' + stepName + '-step');
    var stateLabel = document.getElementById('ethereum-' + stepName + '-step-state');
    if (step) step.dataset.state = state;
    if (stateLabel) stateLabel.textContent = label;
    if (message) {
        var status = document.getElementById('ethereum-' + stepName + '-status');
        if (status) status.textContent = message;
    }
}

function ethereumShowContextualAction(id, visible) {
    var action = document.getElementById(id);
    if (!action) return;
    action.classList.toggle('hidden', !visible);
}

function ethereumUpdateSetupDisclosure(setupComplete) {
    var disclosure = document.getElementById('ethereum-setup');
    if (!disclosure) return;
    // Pick a useful default only on first load and readiness transitions.
    // Ordinary polling must preserve a person's manual open/closed choice.
    if (!ethereumWalletUi.setupDisclosureInitialized ||
        ethereumWalletUi.setupComplete !== setupComplete) {
        disclosure.open = !setupComplete;
    }
    ethereumWalletUi.setupDisclosureInitialized = true;
    ethereumWalletUi.setupComplete = setupComplete;
}

function ethereumAccountCheckPresentation(check) {
    if (!check || !Number.isSafeInteger(check.created_at_unix) ||
        !Number.isSafeInteger(check.expires_at_unix)) return null;
    var elapsed = Math.max(0, Math.floor(Date.now() / 1000) - check.created_at_unix);
    var age = ethereumDuration(elapsed) + ' ago';
    var presentations = {
        queued: ['Request queued', 'The request is queued on this device (' + age + ').', true],
        service_contact_required: ['Account check paused', 'Add the selected Ethereum service\'s Ratspeak contact card. Ratspeak will resume this request automatically (' + age + ').', true],
        sending: ['Sending request', 'Ratspeak is handing the request to your Ethereum service (' + age + ').', true],
        waiting_for_gateway: ['Waiting for service', 'The request was handed to Ratspeak\'s outbound queue. Waiting for the Ethereum service to return evidence (' + age + ').', true],
        awaiting_download_approval: ['Download approval needed', 'The Ethereum service offered evidence. Review the requested download to continue.', true],
        verifying: ['Verifying evidence', 'Evidence arrived. Ratspeak is verifying it locally against the approved checkpoint.', true],
        completed: ['Account check completed', 'The latest account request completed.', false],
        failed: ['Account check stopped', 'The service could not complete this account check, or the request expired. Your displayed balance was not changed. Try again or choose another service.', false]
    };
    var value = presentations[check.stage];
    if (!value) return null;
    var retry = check.stage === 'failed' ||
        check.stage === 'waiting_for_gateway' && elapsed >= 120;
    return {
        label: value[0],
        message: retry && check.stage === 'waiting_for_gateway'
            ? value[1] + ' If delivery failed, you can retry the same bounded request.'
            : value[1],
        active: value[2],
        retry: retry
    };
}

function ethereumRenderAccountCheckTimes(check) {
    var details = document.getElementById('ethereum-account-check-times');
    if (!details) return;
    var valid = check && Number.isSafeInteger(check.created_at_unix) &&
        Number.isSafeInteger(check.expires_at_unix) &&
        check.created_at_unix > 0 && check.expires_at_unix > check.created_at_unix;
    details.classList.toggle('hidden', !valid);
    if (!valid) return;
    var created = new Date(check.created_at_unix * 1000);
    var expires = new Date(check.expires_at_unix * 1000);
    document.getElementById('ethereum-account-check-created-local').textContent = created.toLocaleString();
    document.getElementById('ethereum-account-check-created-unix').textContent = String(check.created_at_unix);
    document.getElementById('ethereum-account-check-expires-local').textContent = expires.toLocaleString();
    document.getElementById('ethereum-account-check-expires-unix').textContent = String(check.expires_at_unix);
}

function ethereumServicePresentation(setup) {
    setup = setup || {};
    var stage = setup.account_check && setup.account_check.stage;
    var selectedService = ethereumSelectedServicePresentation(setup.selected_service);
    var serviceName = selectedService
        ? selectedService.displayName : 'the selected Ethereum service';
    if (!setup.gateway_selected) {
        return {
            label: 'No service selected',
            message: setup.public_service_contact_added === true
                ? 'The public test service is in Ratspeak Contacts. Choose it to continue.'
                : 'Add a public Sepolia service to Contacts, or choose another verified Contact. Selection alone will not be shown as connected.',
            reachable: false
        };
    }
    if (!setup.gateway_contact_ready) {
        return {
            label: 'Service selected · Contact needed',
            message: 'Service selected. Add the matching operator in Ratspeak Contacts before Ratspeak accepts a response.',
            reachable: false
        };
    }
    if (stage === 'sending' || stage === 'waiting_for_gateway') {
        return {
            label: 'Waiting for RPC response',
            message: 'Waiting for an RPC response from ' + serviceName +
                '; reachability is not confirmed yet.',
            reachable: false
        };
    }
    if (stage === 'awaiting_download_approval' || stage === 'verifying' ||
        stage === 'completed') {
        return {
            label: 'Reachable',
            message: serviceName +
                ' returned an RPC response. Ratspeak still verifies Ethereum evidence locally.',
            reachable: true
        };
    }
    return {
        label: 'Contact added · Service selected',
        message: 'The matching Ratspeak Contact is available. Reachability will be checked when you check your account.',
        reachable: false
    };
}

// Checkpoint details are a read-only, public audit trail. The native layer is
// still the authority for installing trust; the WebView receives no approval
// controls, checkpoint bytes, or provider input.
function ethereumRenderCheckpointDetails(checkpoint) {
    var details = document.getElementById('ethereum-checkpoint-details');
    if (!details) return;
    var valid = checkpoint && Number.isSafeInteger(checkpoint.epoch) &&
        typeof checkpoint.root === 'string' && /^0x[0-9a-fA-F]{64}$/.test(checkpoint.root);
    details.classList.toggle('hidden', !valid);
    var copy = document.getElementById('ethereum-copy-checkpoint-root-btn');
    if (copy) copy.disabled = !valid;
    if (!valid) return;

    document.getElementById('ethereum-checkpoint-epoch').textContent = String(checkpoint.epoch);
    var root = checkpoint.root.toLowerCase();
    document.getElementById('ethereum-checkpoint-root').textContent = root;
    var knownOnline = checkpoint.approval_basis === 'provider_agreement' &&
        checkpoint.known_online_provider_agreement === true;
    var basis = knownOnline
        ? 'The built-in ethPandaOps and ChainSafe sources agreed on this exact epoch and root.'
        : checkpoint.approval_basis === 'provider_agreement'
        ? 'Stored records show agreement between configured source identifiers, but this build cannot identify them as its built-in online sources.'
        : checkpoint.approval_basis === 'explicit_user_approval'
        ? 'This checkpoint was explicitly approved by you from a custom source.'
        : 'This checkpoint was accepted under the configured local trust policy.';
    var bootstrap = checkpoint.local_bootstrap_verified === true
        ? knownOnline
            ? ' Ratspeak also verified separately acquired light-client bootstrap data locally with Helios.'
            : checkpoint.approval_basis === 'explicit_user_approval'
            ? ' Ratspeak locally verified the approved checkpoint card’s light-client bootstrap data with Helios.'
            : ' Ratspeak locally verified bootstrap data with Helios before installation.'
        : ' Local bootstrap verification status was not supplied.';
    document.getElementById('ethereum-checkpoint-verification-summary').textContent = basis + bootstrap;

    var bootstrapSource = document.getElementById('ethereum-checkpoint-bootstrap-source');
    var bootstrapLink = document.getElementById('ethereum-checkpoint-bootstrap-link');
    if (bootstrapSource) bootstrapSource.classList.toggle('hidden', !knownOnline);
    if (bootstrapLink) {
        bootstrapLink.href = knownOnline
            ? 'https://ethereum-sepolia-beacon-api.publicnode.com/eth/v1/beacon/light_client/bootstrap/' + root
            : '#';
    }

    function renderTime(id, unix) {
        var local = document.getElementById(id + '-local');
        var raw = document.getElementById(id + '-unix');
        var validTime = Number.isSafeInteger(unix) && unix > 0;
        if (local) local.textContent = validTime ? new Date(unix * 1000).toLocaleString() : 'Not supplied';
        if (raw) raw.textContent = validTime ? String(unix) : 'Not supplied';
    }
    renderTime('ethereum-checkpoint-approved', checkpoint.approved_at_unix);
    renderTime('ethereum-checkpoint-valid-until', checkpoint.valid_until_unix);

    var list = document.getElementById('ethereum-checkpoint-sources');
    while (list && list.firstChild) list.removeChild(list.firstChild);
    var sources = Array.isArray(checkpoint.sources) ? checkpoint.sources : [];
    sources.forEach(function(source) {
        if (!list || !source || typeof source.name !== 'string') return;
        var item = document.createElement('li');
        item.appendChild(document.createTextNode(source.name));
        var url = typeof source.status_url === 'string' ? source.status_url : source.url;
        if (/^https:\/\//.test(url || '')) {
            var link = document.createElement('a');
            link.href = url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.textContent = 'Check source';
            item.appendChild(document.createTextNode(' — '));
            item.appendChild(link);
        }
        if (Number.isSafeInteger(source.observed_at_unix) && source.observed_at_unix > 0) {
            item.appendChild(document.createTextNode(' (observed ' + new Date(source.observed_at_unix * 1000).toLocaleString() + ')'));
        }
        list.appendChild(item);
    });
    if (list && !list.firstChild) {
        var fallback = document.createElement('li');
        fallback.textContent = 'Source names were not supplied for this approval. Compare the root with an independent Sepolia Beacon API.';
        list.appendChild(fallback);
    }
}

function ethereumScheduleAccountCheckPoll(active) {
    if (ethereumWalletUi.nativeCeremonyActive) active = false;
    if (!active) {
        if (ethereumWalletUi.accountCheckPollTimer !== null) {
            clearTimeout(ethereumWalletUi.accountCheckPollTimer);
            ethereumWalletUi.accountCheckPollTimer = null;
        }
        return;
    }
    if (ethereumWalletUi.accountCheckPollTimer !== null) return;
    ethereumWalletUi.accountCheckPollTimer = setTimeout(function() {
        ethereumWalletUi.accountCheckPollTimer = null;
        if (typeof currentView === 'string' && currentView === 'ethereum') {
            loadEthereumWalletView({ preserveVisibleState: true });
        }
    }, 2000);
}

function ethereumRenderSetupStatus(setup, nativeState) {
    setup = setup || {};
    var walletReady = setup.wallet_configured === true;
    var checkpointReady = setup.checkpoint_installed === true;
    var gatewaySelected = setup.gateway_selected === true;
    var gatewayContactReady = setup.gateway_contact_ready === true;
    var gatewayReady = setup.gateway_configured === true;
    var service = ethereumServicePresentation(setup);
    var accountCheck = ethereumAccountCheckPresentation(setup.account_check);
    var accountCheckActive = accountCheck && accountCheck.active;
    var accountReady = ethereumWalletUi.account &&
        ethereumWalletUi.account.assurance === 'current_verified';
    var checkpointMessage = ethereumWalletUi.connectingSepolia
        ? ethereumWalletUi.checkpointFeedback
        : ethereumWalletUi.checkpointFeedbackError
        ? ethereumWalletUi.checkpointFeedback
        : checkpointReady
        ? 'A Sepolia checkpoint agreed by the configured providers is stored for this Ratspeak profile.'
        : setup.pending_checkpoint_review
        ? 'A checkpoint candidate is ready for your secure review.'
        : ethereumWalletUi.checkpointFeedback ||
            'Ratspeak will compare current checkpoints from ethPandaOps and ChainSafe, then verify separate light-client data locally.';
    var gatewayMessage = ethereumWalletUi.addingPublicService
        ? ethereumWalletUi.gatewayFeedback
        : ethereumWalletUi.gatewayFeedbackError
        ? ethereumWalletUi.gatewayFeedback
        : setup.pending_gateway_review
        ? 'A selected Ethereum service is ready for secure review.'
        : service.message;
    var syncMessage = ethereumWalletUi.syncFeedbackError
        ? ethereumWalletUi.syncFeedback
        : accountCheckActive || accountCheck && setup.account_check.stage === 'failed'
        ? accountCheck.message
        : accountReady
        ? 'Your account state was verified locally against the approved checkpoint.'
        : accountCheck
        ? accountCheck.message
        : ethereumWalletUi.syncFeedback ||
            (!walletReady ? 'Create or import a wallet before checking an account.' :
            checkpointReady && gatewayReady ? 'Ready to request and verify your account evidence.' :
            'Bootstrap a trusted checkpoint and choose an Ethereum service from your Ratspeak Contacts to continue.');

    ethereumSetStep('wallet', walletReady ? 'complete' : 'current',
        walletReady ? 'Wallet ready' : nativeState.setupRequired ? 'Setup required' :
        nativeState.enabled ? 'Ready to set up' : 'Needs attention');
    ethereumSetStep('checkpoint', checkpointReady ? 'complete' :
        setup.pending_checkpoint_review ? 'current' : 'pending',
        checkpointReady ? 'Checkpoint bootstrapped' : setup.pending_checkpoint_review ? 'Review required' : 'Not bootstrapped',
        checkpointMessage);
    ethereumSetStep('gateway', gatewayReady ? 'complete' :
        setup.pending_gateway_review ? 'current' : 'pending',
        setup.pending_gateway_review ? 'Review required' : service.label,
        gatewayMessage);
    ethereumSetStep('sync', accountCheckActive ? 'current' :
        accountCheck && setup.account_check.stage === 'failed' ? 'error' :
        accountReady ? 'complete' :
        walletReady && checkpointReady && gatewayReady ? 'current' : 'pending',
        accountCheckActive || accountCheck && setup.account_check.stage === 'failed' ? accountCheck.label :
        accountReady ? 'Account verified' : accountCheck ? accountCheck.label :
        walletReady && checkpointReady && gatewayReady ? 'Ready' : 'Waiting for setup',
        syncMessage);

    document.getElementById('ethereum-import-checkpoint-file-btn').textContent =
        checkpointReady ? 'Import replacement checkpoint file' : 'Choose checkpoint file';
    document.getElementById('ethereum-import-gateway-card-btn').textContent =
        ethereumWalletUi.featureStatus && ethereumWalletUi.featureStatus.native_gateway_pairing === 'file'
        ? gatewaySelected ? 'Import replacement service card' : 'Import service card'
        : gatewaySelected ? 'Change service' : 'Choose Ethereum service';
    var gatewayPairingNote = document.getElementById('ethereum-gateway-pairing-note');
    if (gatewayPairingNote) {
        gatewayPairingNote.textContent = ethereumWalletUi.featureStatus &&
            ethereumWalletUi.featureStatus.native_gateway_pairing === 'file'
            ? 'Android preview currently imports a service card file. Choosing directly from Ratspeak Contacts is not available yet.'
            : 'Ratspeak opens your profile’s verified Contacts and rechecks the selected identity before saving it.';
    }
    document.getElementById('ethereum-open-contacts-btn').textContent =
        gatewayContactReady ? 'View service in Contacts' : 'Choose from Ratspeak Contacts';

    ethereumShowContextualAction('ethereum-review-pending-checkpoint-btn',
        setup.pending_checkpoint_review === true);
    ethereumShowContextualAction('ethereum-connect-sepolia-btn',
        setup.pending_checkpoint_review !== true);
    ethereumShowContextualAction('ethereum-change-checkpoint-btn', checkpointReady);
    ethereumShowContextualAction('ethereum-review-gateway-card-btn',
        setup.pending_gateway_review === true);
    ethereumShowContextualAction('ethereum-add-public-service-btn',
        setup.public_service_available === true && setup.public_service_contact_added !== true);
    ethereumShowContextualAction('ethereum-open-contacts-btn',
        setup.pending_gateway_review !== true);
    ethereumShowContextualAction('ethereum-review-pending-evidence-btn',
        setup.pending_evidence_review === true);
    // Step 4 is a linear prerequisite-gated action, not an attractive control
    // that users can probe while wallet, checkpoint, or service setup is
    // incomplete. The backend independently enforces the same boundaries.
    ethereumShowContextualAction('ethereum-sync-btn',
        walletReady && checkpointReady && gatewayReady);
    document.getElementById('ethereum-setup-summary').textContent =
        ethereumWalletUi.setupRefreshFailed ? 'Status unavailable' :
        accountCheckActive ? accountCheck.label :
        accountCheck && setup.account_check.stage === 'failed' ? 'Needs attention' :
        walletReady && checkpointReady && gatewayReady && accountReady ? 'Ready to send' :
        walletReady && checkpointReady && gatewayReady ? 'Ready to check account' : 'Setup incomplete';
    ethereumUpdateSetupDisclosure(
        walletReady && checkpointReady && gatewayReady && accountReady);
    document.getElementById('ethereum-sync-btn').textContent =
        accountCheck && accountCheck.retry ? 'Retry account check' :
        accountCheckActive ? 'Checking account…' : 'Check my account';
    document.getElementById('ethereum-sync-btn').setAttribute('aria-busy',
        accountCheckActive && !accountCheck.retry ? 'true' : 'false');
    document.getElementById('ethereum-connect-sepolia-btn').textContent =
        ethereumWalletUi.connectingSepolia ? 'Checking two Sepolia sources…' :
        checkpointReady ? 'Check for newer checkpoint' : 'Bootstrap Sepolia checkpoint';
    document.getElementById('ethereum-connect-sepolia-btn').setAttribute('aria-busy',
        ethereumWalletUi.connectingSepolia ? 'true' : 'false');
    document.getElementById('ethereum-add-public-service-btn').setAttribute('aria-busy',
        ethereumWalletUi.addingPublicService ? 'true' : 'false');
    ethereumRenderAccountCheckTimes(setup.account_check);
    ethereumRenderCheckpointDetails(setup.checkpoint);
    ethereumScheduleAccountCheckPoll(accountCheckActive);
}

function ethereumCanonicalDecimal(value, fractionalDigits) {
    value = String(value == null ? '' : value).trim();
    var match = /^(0|[1-9][0-9]*)(?:\.([0-9]+))?$/.exec(value);
    if (!match || (match[2] || '').length > fractionalDigits) return null;
    var fraction = match[2] || '';
    return match[1] + fraction.padEnd(fractionalDigits, '0');
}

function ethereumDecimalToBaseUnits(value, fractionalDigits) {
    var digits = ethereumCanonicalDecimal(value, fractionalDigits);
    if (digits === null) return null;
    digits = digits.replace(/^0+(?=[0-9])/, '');
    return digits || '0';
}

function ethereumWeiToEth(wei) {
    wei = String(wei == null ? '' : wei);
    if (!/^(0|[1-9][0-9]*)$/.test(wei)) return '...';
    var padded = wei.padStart(19, '0');
    var whole = padded.slice(0, -18).replace(/^0+(?=[0-9])/, '') || '0';
    var fraction = padded.slice(-18).replace(/0+$/, '');
    return whole + (fraction ? '.' + fraction : '') + ' ETH';
}

function ethereumNormalizeTransactionHash(value) {
    value = String(value == null ? '' : value);
    var encoded = value.replace(/^0x/, '');
    return /^[0-9a-fA-F]{64}$/.test(encoded) ? '0x' + encoded.toLowerCase() : null;
}

function ethereumNormalizeTransferIntent(fields) {
    fields = fields || {};
    var recipient = String(fields.recipient || '').trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(recipient) || /^0x0{40}$/i.test(recipient)) {
        return { error: 'Enter a non-zero 0x-prefixed Ethereum recipient.' };
    }
    var valueWei = ethereumDecimalToBaseUnits(fields.valueEth, 18);
    var maxFeeWei = ethereumDecimalToBaseUnits(fields.maxFeeGwei, 9);
    var priorityFeeWei = ethereumDecimalToBaseUnits(fields.priorityFeeGwei, 9);
    var maxU256 = (1n << 256n) - 1n;
    var maxU128 = (1n << 128n) - 1n;
    if (valueWei === null || BigInt(valueWei) === 0n || BigInt(valueWei) > maxU256) {
        return { error: 'Enter an ETH amount greater than zero with at most 18 decimal places.' };
    }
    if (maxFeeWei === null || BigInt(maxFeeWei) === 0n || BigInt(maxFeeWei) > maxU128) {
        return { error: 'Enter a max fee greater than zero with at most 9 decimal places.' };
    }
    if (priorityFeeWei === null || BigInt(priorityFeeWei) > maxU128) {
        return { error: 'Enter a priority fee with at most 9 decimal places.' };
    }
    if (BigInt(priorityFeeWei) > BigInt(maxFeeWei)) {
        return { error: 'Priority fee cannot exceed the max fee.' };
    }
    var maximumFeeWei = BigInt(maxFeeWei) * ETHEREUM_NATIVE_TRANSFER_GAS;
    var maximumTotalWei = BigInt(valueWei) + maximumFeeWei;
    if (maximumTotalWei > maxU256) {
        return { error: 'Amount plus maximum fee is too large.' };
    }
    return {
        request: {
            kind: 'transfer',
            recipient: recipient,
            value_wei: valueWei,
            max_fee_per_gas_wei: maxFeeWei,
            max_priority_fee_per_gas_wei: priorityFeeWei
        },
        amountDisplay: ethereumWeiToEth(valueWei),
        feeDisplay: ethereumWeiToEth(maximumFeeWei.toString()),
        totalDisplay: ethereumWeiToEth(maximumTotalWei.toString())
    };
}

function ethereumAccountPresentation(account) {
    var view = {
        address: account && /^0x[0-9a-fA-F]{40}$/.test(account.address || '')
            ? account.address : null,
        balance: '...',
        nonce: '...',
        evidenceAge: '...',
        assurance: 'No verified account proof'
    };
    if (!account || account.assurance === 'unknown') return view;
    if (account.assurance === 'stale') {
        view.assurance = 'Verified account proof is stale';
        if (Number.isSafeInteger(account.evidence_age_seconds) && account.evidence_age_seconds >= 0) {
            view.evidenceAge = ethereumDuration(account.evidence_age_seconds) + ' (stale)';
        }
        return view;
    }
    if (account.assurance !== 'current_verified') return view;
    view.assurance = 'Account proof verified';
    // The node emits CurrentVerified only for chain-time-current, exact account
    // proof evidence. Every weaker state remains an ellipsis, including stale zero.
    if (/^(0|[1-9][0-9]*)$/.test(account.balance_display || '')) {
        view.balance = ethereumWeiToEth(account.balance_display);
    }
    if (/^(0|[1-9][0-9]*)$/.test(account.nonce_display || '')) {
        view.nonce = account.nonce_display;
    }
    if (Number.isSafeInteger(account.evidence_age_seconds) && account.evidence_age_seconds >= 0) {
        view.evidenceAge = ethereumDuration(account.evidence_age_seconds);
    }
    return view;
}

function ethereumDuration(seconds) {
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
    return Math.floor(seconds / 86400) + 'd';
}

function ethereumBlockNumber(value) {
    return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function ethereumBlockDistance(headNumber, includedNumber) {
    var distance = headNumber - includedNumber;
    if (distance === 0) return 'at the inclusion block in this RPC status';
    var count = Math.abs(distance);
    return ethereumBlockNumber(count) + ' block' + (count === 1 ? '' : 's') +
        (distance > 0 ? ' past' : ' behind') + ' the inclusion block';
}

function ethereumSelectedServicePresentation(selectedService) {
    if (!selectedService || typeof selectedService.display_name !== 'string' ||
        typeof selectedService.destination_fingerprint !== 'string' ||
        typeof selectedService.avatar_seed !== 'string') return null;
    var displayName = selectedService.display_name.trim();
    if (!displayName || displayName.length > 64 || /[\u0000-\u001f\u007f]/.test(displayName) ||
        !/^[0-9a-f]{4}…[0-9a-f]{4}$/.test(selectedService.destination_fingerprint) ||
        !/^[0-9a-f]{32}$/.test(selectedService.avatar_seed)) return null;
    var expectedFingerprint = selectedService.avatar_seed.slice(0, 4) + '…' +
        selectedService.avatar_seed.slice(-4);
    if (selectedService.destination_fingerprint !== expectedFingerprint) return null;
    return {
        displayName: displayName,
        destinationFingerprint: selectedService.destination_fingerprint,
        avatarSeed: selectedService.avatar_seed
    };
}

function ethereumRenderServiceContact(prefix, selectedService, visible) {
    var container = document.getElementById(prefix + '-contact');
    var avatar = document.getElementById(prefix + '-avatar');
    var name = document.getElementById(prefix + '-name');
    if (!container || !avatar || !name) return;
    var show = Boolean(selectedService && visible);
    container.classList.toggle('hidden', !show);
    avatar.innerHTML = '';
    name.textContent = show ? selectedService.displayName : '';
    if (show && typeof identityAvatar === 'function') {
        // avatarSeed is the already-public canonical LXMF Contact destination.
        // Reuse the global Contacts renderer so this blockie matches everywhere.
        avatar.innerHTML = identityAvatar(selectedService.avatarSeed, 40);
    }
}

function ethereumTransactionStatusObservationPresentation(observation) {
    if (!observation || observation.authority !== 'rpc_status' ||
        !/^(not_seen|pending|included)$/.test(observation.status || '') ||
        !Number.isSafeInteger(observation.observed_at_unix) || observation.observed_at_unix <= 0 ||
        !/^[0-9a-f]{32}$/.test(observation.source_hash || '')) return null;

    var blockHash = /^0x[0-9a-f]{64}$/;
    var headNames = ['latest', 'safe', 'finalized'];
    var heads = {};
    if (!observation.heads) return null;
    for (var index = 0; index < headNames.length; index++) {
        var name = headNames[index];
        var head = observation.heads[name];
        if (!head || !Number.isSafeInteger(head.number) || head.number <= 0 ||
            !blockHash.test(head.hash || '')) return null;
        heads[name] = { number: head.number, hash: head.hash };
    }
    if (heads.finalized.number > heads.safe.number || heads.safe.number > heads.latest.number) return null;

    var included = null;
    if (observation.status === 'included') {
        if (!observation.included_block ||
            !Number.isSafeInteger(observation.included_block.number) ||
            observation.included_block.number <= 0 ||
            observation.included_block.number > heads.latest.number ||
            !blockHash.test(observation.included_block.hash || '')) return null;
        included = {
            number: observation.included_block.number,
            hash: observation.included_block.hash
        };
    } else if (observation.included_block !== null) {
        return null;
    }

    var continuity = observation.continuity || 'observed';
    if (!/^(observed|awaiting_reinclusion|inconsistent)$/.test(continuity)) return null;
    var previousInclusion = null;
    if (continuity !== 'observed') {
        if (!observation.previous_inclusion ||
            !Number.isSafeInteger(observation.previous_inclusion.number) ||
            observation.previous_inclusion.number <= 0 ||
            !blockHash.test(observation.previous_inclusion.hash || '') ||
            !Number.isSafeInteger(observation.previous_inclusion.observed_at_unix) ||
            observation.previous_inclusion.observed_at_unix <= 0 ||
            continuity === 'awaiting_reinclusion' && observation.status === 'included') return null;
        previousInclusion = {
            number: observation.previous_inclusion.number,
            hash: observation.previous_inclusion.hash,
            observedAtUnix: observation.previous_inclusion.observed_at_unix
        };
    } else if (observation.previous_inclusion !== null) {
        return null;
    }

    return {
        status: observation.status,
        observedAtUnix: observation.observed_at_unix,
        sourceHash: observation.source_hash,
        continuity: continuity,
        included: included,
        previousInclusion: previousInclusion,
        heads: heads
    };
}

function ethereumTransactionTimeline(transaction, observation, selectedService, fallbackRpcSourceName) {
    if (!transaction) {
        return [{
            label: 'No transaction yet',
            detail: 'Review and sign a transaction to see durable progress here.',
            authority: 'This device',
            state: 'empty'
        }];
    }
    var ranks = {
        signed_locally: 0,
        transport_delivered: 1,
        gateway_acknowledged: 2,
        rpc_accepted: 3,
        receipt_verifying: 2,
        finalized: 2
    };
    var rank = Object.prototype.hasOwnProperty.call(ranks, transaction.progress)
        ? ranks[transaction.progress] : 0;
    var hasObservation = Boolean(observation);
    var rpcSourceName = selectedService
        ? selectedService.displayName : fallbackRpcSourceName || 'your selected Ethereum service';
    var rpcSourceAuthority = 'RPC status from ' + rpcSourceName;
    var assuranceVerified = transaction.assurance === 'verified_success' ||
        transaction.assurance === 'verified_failure';
    var rpcLabel = rank >= 3 ? 'RPC accepted' : 'Awaiting RPC status';
    var rpcDetail = rank >= 3
        ? 'RPC acceptance status came from ' + rpcSourceName + '. This is not Ethereum confirmation.'
        : 'No RPC status from ' + rpcSourceName + ' is available yet.';
    var rpcState = rank >= 3 ? 'reported' : 'waiting';
    var inclusionLabel = 'Waiting for RPC inclusion status';
    var inclusionDetail = 'No RPC status from ' + rpcSourceName + ' places this transaction in a block yet.';
    var inclusionState = 'waiting';
    var inclusionAuthority = rpcSourceAuthority;
    var headsLabel = 'Network confirmation progress';
    var headsDetail = '';
    var headsState = 'waiting';

    if (observation) {
        if (observation.status === 'not_seen') {
            rpcLabel = 'Not currently visible to this service';
            rpcDetail = 'RPC status from ' + rpcSourceName + ' does not currently show the transaction. This does not mean it failed.';
            rpcState = 'current';
            inclusionLabel = 'Awaiting visibility';
            inclusionDetail = 'The transaction may still propagate or appear in a later RPC status update.';
            inclusionState = 'waiting';
        } else if (observation.status === 'pending') {
            rpcLabel = 'RPC status: pending';
            rpcDetail = 'RPC status from ' + rpcSourceName + ' shows the transaction as pending. This is not confirmation.';
            rpcState = 'reported';
            inclusionLabel = 'Pending — not included';
            inclusionDetail = 'The latest RPC status does not include a block yet.';
            inclusionState = 'current';
        } else {
            rpcLabel = 'RPC status: included';
            rpcDetail = 'RPC status from ' + rpcSourceName + ' shows block inclusion. This is not receipt proof.';
            rpcState = 'reported';
            inclusionLabel = 'RPC sees transaction in block ' + ethereumBlockNumber(observation.included.number);
            inclusionDetail = 'Status from ' + rpcSourceName + ' only — awaiting receipt proof verified on this device.';
            inclusionState = assuranceVerified ? 'complete' : 'reported';
        }
        if (observation.continuity === 'awaiting_reinclusion') {
            inclusionLabel = 'Awaiting reinclusion';
            inclusionDetail = 'A previous RPC inclusion status is no longer present. No transaction failure has been verified.';
            inclusionState = 'warning';
        } else if (observation.continuity === 'inconsistent') {
            inclusionLabel = 'Inconsistent RPC status';
            inclusionDetail = 'RPC observations disagree. Ratspeak is waiting for a consistent status; no failure has been verified.';
            inclusionState = 'warning';
        }

        var headParts = [];
        if (observation.included) {
            headParts = [
                'Newest block ' + ethereumBlockNumber(observation.heads.latest.number) + ' — ' +
                    ethereumBlockDistance(observation.heads.latest.number, observation.included.number),
                'Safe block ' + ethereumBlockNumber(observation.heads.safe.number) + ' — ' +
                    ethereumBlockDistance(observation.heads.safe.number, observation.included.number),
                'Finalized block ' + ethereumBlockNumber(observation.heads.finalized.number) + ' — ' +
                    ethereumBlockDistance(observation.heads.finalized.number, observation.included.number)
            ];
        }
        headsDetail = headParts.join(' · ') + '. Status from ' + rpcSourceName +
            '; Ratspeak still requires the exact receipt proof.';
        headsState = 'reported';
    } else if (assuranceVerified) {
        inclusionLabel = 'Included in verified finalized receipt';
        inclusionDetail = 'Receipt proof verified on this device establishes inclusion; the block number is not exposed in this summary.';
        inclusionState = 'complete';
        inclusionAuthority = 'Receipt proof verified on this device';
    }

    var receiptLabel = 'Awaiting exact finalized receipt';
    var receiptDetail = 'Only local verification of the exact finalized receipt can confirm success or failure.';
    var receiptState = 'waiting';
    var receiptEligible = Boolean(observation && observation.included &&
        observation.heads.finalized.number >= observation.included.number);
    var receiptRequestState = receiptEligible && transaction.receipt_request &&
        transaction.receipt_request.state;
    if (receiptRequestState === 'requested') {
        receiptLabel = 'Receipt proof requested';
        receiptDetail = 'Ratspeak requested the exact finalized receipt from ' + rpcSourceName + '.';
        receiptState = 'current';
    } else if (receiptRequestState === 'awaiting_download') {
        receiptLabel = 'Preparing receipt download';
        receiptDetail = 'The expected bounded receipt package is ready to download from ' + rpcSourceName + '.';
        receiptState = 'current';
    } else if (receiptRequestState === 'downloading') {
        receiptLabel = 'Downloading receipt proof';
        receiptDetail = 'Ratspeak is receiving the expected bounded receipt package from ' + rpcSourceName + '.';
        receiptState = 'current';
    } else if (receiptRequestState === 'verifying' || receiptRequestState === 'complete') {
        receiptLabel = 'Verifying receipt proof';
        receiptDetail = 'The exact receipt package is on this device and local verification is running.';
        receiptState = 'current';
    } else if (receiptRequestState === 'unavailable') {
        receiptLabel = 'Receipt proof needs retry';
        receiptDetail = 'The previous receipt request ended before local verification completed.';
        receiptState = 'warning';
    }
    if (transaction.assurance === 'verified_success') {
        receiptLabel = 'Confirmed';
        receiptDetail = 'Receipt proof verified on this device confirms this transaction.';
        receiptState = 'verified';
    } else if (transaction.assurance === 'verified_failure') {
        receiptLabel = 'Failed';
        receiptDetail = 'Receipt proof verified on this device confirms transaction failure.';
        receiptState = 'error';
    } else if (transaction.assurance === 'receipt_needs_reverification') {
        receiptLabel = 'Receipt needs reverification';
        receiptDetail = 'Receipt evidence exists, but Ratspeak must verify it again before showing an outcome.';
        receiptState = 'current';
    }

    var timeline = [
        {
            label: 'Signed locally',
            detail: 'The exact signed transaction is stored on this device.',
            authority: 'This device',
            state: 'complete'
        },
        {
            label: rank >= 1 || hasObservation ? 'Handed to Ratspeak transport' : 'Waiting to send',
            detail: rank >= 1 || hasObservation
                ? 'Ratspeak handed the signed transaction to its Reticulum transport.'
                : 'The signed transaction has not yet been handed to Reticulum.',
            authority: 'Ratspeak',
            state: rank >= 1 || hasObservation ? 'complete' : 'current'
        },
        {
            label: rank >= 2 || hasObservation ? 'Ethereum service response' : 'Awaiting service response',
            detail: rank >= 2 || hasObservation
                ? selectedService
                    ? 'A response from ' + selectedService.displayName + ' is stored.'
                    : 'A response from an Ethereum service is stored.'
                : 'Your selected Ethereum service has not returned a response yet.',
            authority: selectedService ? selectedService.displayName : 'Ethereum service',
            sourceContact: selectedService,
            state: rank >= 2 || hasObservation ? 'complete' : 'waiting'
        },
        {
            label: rpcLabel,
            detail: rpcDetail,
            authority: rpcSourceAuthority,
            sourceContact: selectedService,
            state: rpcState
        },
        {
            label: inclusionLabel,
            detail: inclusionDetail,
            authority: inclusionAuthority,
            sourceContact: selectedService,
            state: inclusionState
        },
        {
            label: headsLabel,
            detail: headsDetail,
            authority: rpcSourceAuthority,
            sourceContact: selectedService,
            state: headsState
        },
        {
            label: receiptLabel,
            detail: receiptDetail,
            authority: receiptState === 'verified' || receiptState === 'error'
                ? 'Receipt proof verified on this device' : 'This device',
            state: receiptState
        }
    ];
    // Chain-head numbers are useful only after there is an inclusion block to
    // compare them with. While pending they are technical network trivia and
    // visually make the progression appear to alternate backward and forward.
    if (!observation || !observation.included) timeline.splice(5, 1);
    // A locally verified finalized receipt already establishes inclusion and
    // the exact outcome. If no RPC-status observation is available, omit that
    // optional intermediate step instead of showing an impossible-looking
    // wait between two completed proof stages. This does not invent RPC
    // acceptance: the receipt-derived inclusion remains explicitly attributed
    // to verification on this device.
    if (assuranceVerified && !observation) timeline.splice(3, 1);
    return timeline;
}

function ethereumTransactionPresentation(transaction, selectedServiceValue) {
    var projectedSelectedService = ethereumSelectedServicePresentation(selectedServiceValue);
    var observation = ethereumTransactionStatusObservationPresentation(
        transaction && transaction.status_observation);
    var selectedServiceMatchesObservation = Boolean(observation && projectedSelectedService &&
        observation.sourceHash === projectedSelectedService.avatarSeed);
    var selectedService = selectedServiceMatchesObservation ? projectedSelectedService : null;
    var fallbackRpcSourceName = observation && projectedSelectedService &&
        !selectedServiceMatchesObservation
        ? 'the Ethereum service that returned this status' : 'your selected Ethereum service';
    var base = {
        hash: transaction ? (ethereumNormalizeTransactionHash(transaction.tx_hash) || '...') : '...',
        assurance: 'No exact verified receipt available',
        note: 'Signed, relayed, and RPC-visible transactions remain unconfirmed until exact receipt evidence verifies locally.',
        verified: false,
        observation: observation,
        selectedService: selectedService,
        timeline: ethereumTransactionTimeline(transaction, observation, selectedService,
            fallbackRpcSourceName)
    };
    if (!transaction) return base;
    if (transaction.assurance === 'signed_unconfirmed') {
        if (transaction.progress === 'rpc_accepted') {
            base.assurance = 'RPC accepted — awaiting finality';
            base.note = 'RPC status from ' + (selectedService
                ? selectedService.displayName : fallbackRpcSourceName) +
                ' shows Sepolia acceptance. This is not confirmation; Ratspeak is waiting for receipt proof verified on this device.';
        } else if (transaction.progress === 'gateway_acknowledged') {
            base.assurance = 'Service acknowledged — not confirmed';
            base.note = 'Your selected Ethereum service acknowledged the transaction. Ratspeak has not yet received RPC acceptance or verified a finalized receipt.';
        } else if (transaction.progress === 'transport_delivered') {
            base.assurance = 'Delivered to service — not confirmed';
            base.note = 'Ratspeak delivered the signed transaction to the selected Ethereum service. Delivery does not prove RPC acceptance or Ethereum confirmation.';
        } else {
            base.assurance = 'Signed locally — not sent';
            base.note = 'The transaction is signed and stored on this device. Ratspeak has not yet delivered it to the Ethereum service.';
        }
    } else if (transaction.assurance === 'receipt_needs_reverification') {
        base.assurance = 'Receipt evidence needs reverification';
    } else if (transaction.assurance === 'verified_success') {
        base.assurance = 'Verified finalized success';
        base.note = 'Receipt proof verified on this device confirms this transaction.';
        base.verified = true;
    } else if (transaction.assurance === 'verified_failure') {
        base.assurance = 'Verified finalized failure';
        base.note = 'Receipt proof verified on this device confirms transaction failure.';
        base.verified = true;
    }
    if (!base.verified && observation) {
        if (observation.continuity === 'awaiting_reinclusion') {
            base.assurance = 'Awaiting reinclusion — not failed';
            base.note = 'A prior RPC inclusion status was superseded. Ratspeak is waiting for consistent RPC status and receipt proof.';
        } else if (observation.continuity === 'inconsistent') {
            base.assurance = 'Inconsistent RPC status — not confirmed';
            base.note = 'RPC observations disagree. No success or failure has been established by receipt proof.';
        } else if (observation.status === 'included') {
            base.assurance = 'Included in a block — verifying';
            base.note = 'RPC status from ' + (selectedService
                ? selectedService.displayName : fallbackRpcSourceName) + ' shows inclusion in block ' +
                ethereumBlockNumber(observation.included.number) +
                '. Only exact finalized receipt verification on this device can confirm the outcome.';
        } else if (observation.status === 'pending') {
            base.assurance = 'Pending on RPC — not confirmed';
            base.note = 'RPC status from ' + (selectedService
                ? selectedService.displayName : fallbackRpcSourceName) +
                ' shows this transaction as pending. This is not confirmation.';
        } else {
            base.assurance = 'Not currently visible to this service';
            base.note = 'RPC status from ' + (selectedService
                ? selectedService.displayName : fallbackRpcSourceName) +
                ' does not currently show this transaction. That does not prove failure.';
        }
    }
    return base;
}

function ethereumNativeUiState(status) {
    if (!status || status.chain_id !== ETHEREUM_SEPOLIA_CHAIN_ID || status.network !== 'sepolia' ||
        status.mainnet_available !== false) {
        return { enabled: false, message: 'Experimental Sepolia feature unavailable.' };
    }
    if (status.platform === 'linux' && status.native_authorization === 'checking') {
        return {
            enabled: true,
            setupRequired: true,
            message: 'Create a wallet or import one with its Secret Recovery Phrase. Linux will first check the system keyring.'
        };
    }
    if ((status.platform !== 'android' && status.platform !== 'linux') ||
        status.native_authorization !== 'available') {
        return { enabled: false, message: 'Native wallet custody is unavailable on this device.' };
    }
    if (status.platform === 'linux') {
        return {
            enabled: true,
            message: 'Linux keeps secret entry, exact review, and authorization in native dialogs.'
        };
    }
    return {
        enabled: true,
        message: 'Android will check biometric and hardware-backed protection inside the native wallet flow.'
    };
}

// Bulk evidence review is a native transport/storage ceremony, not wallet
// custody. It may be available before a wallet exists or when secret custody
// is unavailable; Rust still validates the active profile, identity, and
// configured gateway before opening a dialog.
function ethereumEvidenceReviewUiState(status) {
    if (!status || status.chain_id !== ETHEREUM_SEPOLIA_CHAIN_ID || status.network !== 'sepolia' ||
        status.mainnet_available !== false) {
        return { enabled: false };
    }
    return {
        enabled: (status.platform === 'android' || status.platform === 'linux') &&
            status.native_bulk_evidence_review === 'available'
    };
}

// Manual checkpoint review is independent of wallet custody and gateway
// configuration. The WebView can only request that native code review the
// next already-staged candidate; it supplies no checkpoint or decision data.
function ethereumCheckpointReviewUiState(status) {
    if (!status || status.chain_id !== ETHEREUM_SEPOLIA_CHAIN_ID || status.network !== 'sepolia' ||
        status.mainnet_available !== false) {
        return { enabled: false };
    }
    return {
        enabled: (status.platform === 'android' || status.platform === 'linux') &&
            status.native_checkpoint_review === 'available'
    };
}

function ethereumCheckpointFileImportUiState(status) {
    if (!status || status.chain_id !== ETHEREUM_SEPOLIA_CHAIN_ID || status.network !== 'sepolia' ||
        status.mainnet_available !== false) {
        return { enabled: false };
    }
    return {
        enabled: (status.platform === 'android' || status.platform === 'linux') &&
            status.native_checkpoint_file_import === 'available'
    };
}

function ethereumTransferFieldsFromDom() {
    return {
        recipient: document.getElementById('ethereum-recipient').value,
        valueEth: document.getElementById('ethereum-value-eth').value,
        maxFeeGwei: document.getElementById('ethereum-max-fee-gwei').value,
        priorityFeeGwei: document.getElementById('ethereum-priority-fee-gwei').value
    };
}

function ethereumRenderTransferSummary() {
    var parsed = ethereumNormalizeTransferIntent(ethereumTransferFieldsFromDom());
    document.getElementById('ethereum-review-amount').textContent = parsed.amountDisplay || '...';
    document.getElementById('ethereum-review-fee').textContent = parsed.feeDisplay || '...';
    document.getElementById('ethereum-review-total').textContent = parsed.totalDisplay || '...';
    return parsed;
}

function ethereumRenderAccount(account) {
    var view = ethereumAccountPresentation(account);
    var address = document.getElementById('ethereum-address');
    address.textContent = view.address || 'Wallet not available';
    address.disabled = !view.address;
    address.dataset.copyValue = view.address || '';
    document.getElementById('ethereum-balance').textContent = view.balance;
    document.getElementById('ethereum-nonce').textContent = view.nonce;
    document.getElementById('ethereum-evidence-age').textContent = view.evidenceAge;
    document.getElementById('ethereum-account-assurance').textContent = view.assurance;
}

function ethereumRenderTransaction(transaction) {
    var selectedService = ethereumWalletUi.setupStatus && ethereumWalletUi.setupStatus.selected_service;
    var view = ethereumTransactionPresentation(transaction, selectedService);
    document.getElementById('ethereum-transaction-hash').textContent = view.hash;
    document.getElementById('ethereum-transaction-assurance').textContent = view.assurance;
    document.getElementById('ethereum-transaction-note').textContent = view.note;
    ethereumRenderServiceContact('ethereum-transaction-service', view.selectedService,
        Boolean(view.observation));
    var updateButton = document.getElementById('ethereum-update-transaction-status-btn');
    var feedback = document.getElementById('ethereum-transaction-status-feedback');
    var updateAvailable = Boolean(transaction && !view.verified);
    updateButton.classList.toggle('hidden', !updateAvailable);
    updateButton.disabled = !updateAvailable || ethereumWalletUi.updatingTransactionStatus;
    updateButton.textContent = ethereumWalletUi.updatingTransactionStatus
        ? 'Requesting update…' : 'Update status';
    updateButton.setAttribute('aria-busy', ethereumWalletUi.updatingTransactionStatus ? 'true' : 'false');
    if (!transaction || view.verified) ethereumWalletUi.transactionStatusFeedback = '';
    feedback.textContent = ethereumWalletUi.transactionStatusFeedback;
    var timeline = document.getElementById('ethereum-transaction-timeline');
    while (timeline.firstChild) timeline.removeChild(timeline.firstChild);
    view.timeline.forEach(function(item) {
        var row = document.createElement('li');
        row.className = 'ethereum-transaction-stage';
        row.dataset.state = item.state;
        var marker = document.createElement('span');
        marker.className = 'ethereum-transaction-stage-marker';
        marker.setAttribute('aria-hidden', 'true');
        var content = document.createElement('div');
        content.className = 'ethereum-transaction-stage-content';
        var heading = document.createElement('div');
        heading.className = 'ethereum-transaction-stage-heading';
        var label = document.createElement('strong');
        label.textContent = item.label;
        var authority = document.createElement('span');
        authority.className = 'ethereum-transaction-authority';
        if (item.sourceContact && typeof identityAvatar === 'function') {
            authority.classList.add('ethereum-transaction-source-contact');
            var sourceAvatar = document.createElement('span');
            sourceAvatar.className = 'ethereum-transaction-source-avatar';
            sourceAvatar.setAttribute('aria-hidden', 'true');
            sourceAvatar.innerHTML = identityAvatar(item.sourceContact.avatarSeed, 24);
            var sourceName = document.createElement('span');
            sourceName.className = 'ethereum-transaction-source-name';
            sourceName.textContent = item.sourceContact.displayName;
            authority.appendChild(sourceAvatar);
            authority.appendChild(sourceName);
        } else {
            authority.textContent = item.authority;
        }
        var detail = document.createElement('p');
        detail.textContent = item.detail;
        heading.appendChild(label);
        heading.appendChild(authority);
        content.appendChild(heading);
        content.appendChild(detail);
        row.appendChild(marker);
        row.appendChild(content);
        timeline.appendChild(row);
    });

    var technical = document.getElementById('ethereum-transaction-technical');
    var facts = document.getElementById('ethereum-transaction-technical-facts');
    while (facts.firstChild) facts.removeChild(facts.firstChild);
    technical.classList.toggle('hidden', !view.observation);
    if (!view.observation) return;
    var observation = view.observation;
    var factRows = [
        ['RPC status authority', 'Ratspeak verified the sender’s identity. This RPC status is not an Ethereum proof.', false],
        ['RPC source hash', observation.sourceHash, true],
        ['Observed (local time)', new Date(observation.observedAtUnix * 1000).toLocaleString(), false],
        ['Observed (Unix)', String(observation.observedAtUnix), true]
    ];
    if (view.selectedService) {
        factRows.splice(1, 0, ['Service destination', view.selectedService.destinationFingerprint, true]);
    }
    if (observation.included) {
        factRows.push(['RPC inclusion block', ethereumBlockNumber(observation.included.number), false]);
        factRows.push(['RPC inclusion hash', observation.included.hash, true]);
    }
    ['latest', 'safe', 'finalized'].forEach(function(name) {
        var title = name.charAt(0).toUpperCase() + name.slice(1);
        factRows.push([title + ' head', ethereumBlockNumber(observation.heads[name].number), false]);
        factRows.push([title + ' head hash', observation.heads[name].hash, true]);
    });
    if (observation.previousInclusion) {
        factRows.push(['Previous RPC inclusion', ethereumBlockNumber(observation.previousInclusion.number), false]);
        factRows.push(['Previous inclusion hash', observation.previousInclusion.hash, true]);
        factRows.push(['Previous status (local time)',
            new Date(observation.previousInclusion.observedAtUnix * 1000).toLocaleString(), false]);
    }
    factRows.forEach(function(fact) {
        var row = document.createElement('div');
        var term = document.createElement('dt');
        var value = document.createElement('dd');
        term.textContent = fact[0];
        value.textContent = fact[1];
        if (fact[2]) value.className = 'mono ethereum-selectable';
        row.appendChild(term);
        row.appendChild(value);
        facts.appendChild(row);
    });
}

function ethereumApplyFeatureStatus(status) {
    ethereumWalletUi.featureStatus = status;
    document.querySelectorAll('.ethereum-feature-entry').forEach(function(entry) {
        entry.classList.remove('hidden');
    });
    var nativeState = ethereumNativeUiState(status);
    var featureReady = status && status.chain_id === ETHEREUM_SEPOLIA_CHAIN_ID &&
        status.network === 'sepolia' && status.mainnet_available === false;
    var setup = ethereumWalletUi.setupStatus || {};
    ethereumRenderServiceContact('ethereum-setup-service',
        ethereumSelectedServicePresentation(setup.selected_service), true);
    var accountCheck = ethereumAccountCheckPresentation(setup.account_check);
    document.getElementById('ethereum-sync-btn').disabled =
        !featureReady || ethereumWalletUi.synchronizing ||
        setup.wallet_configured !== true ||
        setup.checkpoint_installed !== true || setup.gateway_configured !== true ||
        Boolean(accountCheck && accountCheck.active && !accountCheck.retry);
    document.getElementById('ethereum-native-status').textContent =
        setup.wallet_configured === true
            ? 'Wallet ready. Recovery and password actions open in a secure system window.'
            : nativeState.enabled
            ? 'Click below, then choose Create wallet or Import wallet in the secure system window.'
            : nativeState.message;
    document.getElementById('ethereum-manage-wallet-btn').textContent =
        setup.wallet_configured === true ? 'Wallet settings' : 'Create or import wallet';
    document.getElementById('ethereum-manage-wallet-btn').disabled =
        ethereumWalletUi.setupRefreshFailed || !nativeState.enabled;
    document.getElementById('ethereum-review-pending-evidence-btn').disabled =
        ethereumWalletUi.setupRefreshFailed ||
        !ethereumEvidenceReviewUiState(status).enabled || setup.pending_evidence_review !== true ||
        ethereumWalletUi.reviewingEvidence;
    document.getElementById('ethereum-review-pending-checkpoint-btn').disabled =
        ethereumWalletUi.setupRefreshFailed ||
        !ethereumCheckpointReviewUiState(status).enabled || setup.pending_checkpoint_review !== true;
    document.getElementById('ethereum-import-checkpoint-file-btn').disabled =
        ethereumWalletUi.setupRefreshFailed || !ethereumCheckpointFileImportUiState(status).enabled;
    document.getElementById('ethereum-connect-sepolia-btn').disabled =
        ethereumWalletUi.setupRefreshFailed || !featureReady ||
        setup.identity_ready !== true || ethereumWalletUi.connectingSepolia;
    document.getElementById('ethereum-add-public-service-btn').disabled =
        ethereumWalletUi.setupRefreshFailed || !featureReady || setup.identity_ready !== true ||
        setup.public_service_available !== true || ethereumWalletUi.addingPublicService;
    var gatewayPairingAvailable = featureReady &&
        (status.native_gateway_pairing === 'contacts' || status.native_gateway_pairing === 'file');
    document.getElementById('ethereum-import-gateway-card-btn').disabled =
        ethereumWalletUi.setupRefreshFailed || !gatewayPairingAvailable;
    document.getElementById('ethereum-review-gateway-card-btn').disabled =
        ethereumWalletUi.setupRefreshFailed ||
        !gatewayPairingAvailable || setup.pending_gateway_review !== true;
    var accountReady = ethereumWalletUi.account &&
        ethereumWalletUi.account.assurance === 'current_verified' &&
        /^0x[0-9a-fA-F]{40}$/.test(ethereumWalletUi.account.address || '');
    document.getElementById('ethereum-review-native-btn').disabled = !(nativeState.enabled && accountReady);
    if (ethereumWalletUi.setupRefreshFailed) {
        document.getElementById('ethereum-review-native-btn').disabled = true;
    }
    ethereumRenderSetupStatus(setup, nativeState);
}

function ethereumLoadLatestTransaction() {
    return RS.invoke(ETHEREUM_UI_COMMANDS.latestTransaction).then(function(transaction) {
        ethereumWalletUi.latestTransaction = transaction || null;
        ethereumWalletUi.latestTransactionLoaded = true;
        ethereumRenderTransaction(ethereumWalletUi.latestTransaction);
        return ethereumWalletUi.latestTransaction;
    }).catch(function() {
        if (!ethereumWalletUi.latestTransactionLoaded) ethereumRenderTransaction(null);
        return ethereumWalletUi.latestTransaction;
    });
}

function ethereumUpdateTransactionStatus() {
    if (ethereumWalletUi.updatingTransactionStatus || !ethereumWalletUi.latestTransaction) {
        return Promise.resolve();
    }
    var selectedService = ethereumWalletUi.setupStatus && ethereumWalletUi.setupStatus.selected_service;
    var view = ethereumTransactionPresentation(ethereumWalletUi.latestTransaction, selectedService);
    if (view.verified) return Promise.resolve();
    ethereumWalletUi.updatingTransactionStatus = true;
    ethereumWalletUi.transactionStatusFeedback =
        'Requesting one RPC status update through Ratspeak…';
    ethereumRenderTransaction(ethereumWalletUi.latestTransaction);
    // No transaction hash or network destination crosses this boundary. Native
    // code selects the latest signed transaction and coalesces/rate-limits work.
    return RS.invoke(ETHEREUM_UI_COMMANDS.updateTransactionStatus).then(function() {
        ethereumWalletUi.transactionStatusFeedback =
            'Status request queued. The timeline will update when RPC status arrives from your selected Ethereum service.';
    }).catch(function() {
        ethereumWalletUi.transactionStatusFeedback =
            'Ratspeak could not request a status update. The last known transaction state is still shown.';
    }).finally(function() {
        ethereumWalletUi.updatingTransactionStatus = false;
        ethereumRenderTransaction(ethereumWalletUi.latestTransaction);
    });
}

function ethereumScheduleTransactionPoll() {
    if (ethereumWalletUi.transactionPollTimer !== null) {
        clearTimeout(ethereumWalletUi.transactionPollTimer);
    }
    if (ethereumWalletUi.nativeCeremonyActive) return;
    ethereumWalletUi.transactionPollTimer = setTimeout(function pollLatestTransaction() {
        ethereumWalletUi.transactionPollTimer = null;
        if (typeof currentView !== 'string' || currentView !== 'ethereum' ||
            !ethereumWalletUi.featureStatus) return;
        ethereumLoadLatestTransaction().finally(ethereumScheduleTransactionPoll);
    }, 2000);
}

function ethereumSetNativeCeremonyActive(active) {
    ethereumWalletUi.nativeCeremonyActive = active === true;
    if (ethereumWalletUi.nativeCeremonyActive) {
        ethereumScheduleAccountCheckPoll(false);
        if (ethereumWalletUi.transactionPollTimer !== null) {
            clearTimeout(ethereumWalletUi.transactionPollTimer);
            ethereumWalletUi.transactionPollTimer = null;
        }
        return;
    }
    if (typeof currentView === 'string' && currentView === 'ethereum') {
        ethereumScheduleTransactionPoll();
        var accountCheck = ethereumWalletUi.setupStatus && ethereumWalletUi.setupStatus.account_check;
        ethereumScheduleAccountCheckPoll(Boolean(accountCheck && ethereumAccountCheckPresentation(accountCheck).active));
    }
}

function loadEthereumWalletView(options) {
    var sequence = ++ethereumWalletUi.refreshSequence;
    var preserveVisibleState = options && options.preserveVisibleState === true;
    if (!preserveVisibleState) {
        ethereumWalletUi.setupStatus = null;
        ethereumWalletUi.account = null;
        ethereumWalletUi.latestTransaction = null;
        ethereumWalletUi.latestTransactionLoaded = false;
        ethereumRenderAccount(null);
        ethereumRenderTransaction(null);
    }
    return RS.invoke(ETHEREUM_UI_COMMANDS.feature).then(function(status) {
        if (sequence !== ethereumWalletUi.refreshSequence) return;
        ethereumApplyFeatureStatus(status);
        return RS.invoke(ETHEREUM_UI_COMMANDS.setup).then(function(setup) {
            var account = setup && setup.account;
            if (!setup || sequence !== ethereumWalletUi.refreshSequence) return;
            var recoveredSetupRefresh = ethereumWalletUi.setupRefreshFailed;
            ethereumWalletUi.setupStatus = setup;
            ethereumWalletUi.account = account || null;
            ethereumWalletUi.setupRefreshFailed = false;
            if (recoveredSetupRefresh) {
                ethereumWalletUi.syncFeedback = null;
                ethereumWalletUi.syncFeedbackError = false;
            }
            ethereumRenderAccount(account || null);
            ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
            return ethereumLoadLatestTransaction().then(ethereumScheduleTransactionPoll);
        }).catch(function() {
            if (sequence !== ethereumWalletUi.refreshSequence) return;
            if (preserveVisibleState && ethereumWalletUi.setupStatus) {
                ethereumWalletUi.setupRefreshFailed = true;
                ethereumWalletUi.syncFeedback =
                    'Ratspeak could not refresh setup status. Your saved wallet, checkpoint, and service have not been erased. Status will be checked again automatically; a safe account retry remains available when shown.';
                ethereumWalletUi.syncFeedbackError = true;
                ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
                ethereumScheduleAccountCheckPoll(true);
                return;
            }
            ethereumWalletUi.setupStatus = null;
            ethereumWalletUi.account = null;
            ethereumWalletUi.setupRefreshFailed = true;
            ethereumRenderAccount(null);
            ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
        });
    }).catch(function() {
        if (sequence !== ethereumWalletUi.refreshSequence) return;
        if (preserveVisibleState && ethereumWalletUi.featureStatus && ethereumWalletUi.setupStatus) {
            ethereumWalletUi.setupRefreshFailed = true;
            ethereumWalletUi.syncFeedback =
                'Ratspeak could not refresh Ethereum availability. Your last confirmed setup is still shown; actions are paused until status can be checked again.';
            ethereumWalletUi.syncFeedbackError = true;
            ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
            return;
        }
        ethereumWalletUi.featureStatus = null;
        ethereumWalletUi.setupStatus = null;
        ethereumWalletUi.account = null;
        ethereumRenderAccount(null);
        document.getElementById('ethereum-native-status').textContent =
            'Experimental Ethereum feature unavailable.';
        document.getElementById('ethereum-manage-wallet-btn').disabled = true;
        document.getElementById('ethereum-review-pending-evidence-btn').disabled = true;
        document.getElementById('ethereum-review-pending-checkpoint-btn').disabled = true;
        document.getElementById('ethereum-import-checkpoint-file-btn').disabled = true;
        document.getElementById('ethereum-connect-sepolia-btn').disabled = true;
        document.getElementById('ethereum-add-public-service-btn').disabled = true;
        document.getElementById('ethereum-import-gateway-card-btn').disabled = true;
        document.getElementById('ethereum-review-gateway-card-btn').disabled = true;
        document.getElementById('ethereum-sync-btn').disabled = true;
        document.getElementById('ethereum-review-native-btn').disabled = true;
        if (ethereumWalletUi.transactionPollTimer !== null) {
            clearTimeout(ethereumWalletUi.transactionPollTimer);
            ethereumWalletUi.transactionPollTimer = null;
        }
        if (ethereumWalletUi.nativeSetupPollTimer !== null) {
            clearTimeout(ethereumWalletUi.nativeSetupPollTimer);
            ethereumWalletUi.nativeSetupPollTimer = null;
        }
        ethereumScheduleAccountCheckPoll(false);
        document.querySelectorAll('.ethereum-feature-entry').forEach(function(entry) {
            entry.classList.add('hidden');
        });
        if (typeof currentView === 'string' && currentView === 'ethereum' &&
            typeof switchView === 'function') {
            switchView(typeof appLandingView === 'function' ? appLandingView() : 'dashboard');
        }
    });
}

function ethereumStartNativeSetupPolling() {
    ethereumWalletUi.nativeSetupPollDeadline = Date.now() + (5 * 60 * 1000);
    if (ethereumWalletUi.nativeSetupPollTimer !== null) return;
    function poll() {
        ethereumWalletUi.nativeSetupPollTimer = null;
        if (Date.now() >= ethereumWalletUi.nativeSetupPollDeadline ||
            typeof currentView !== 'string' || currentView !== 'ethereum') return;
        loadEthereumWalletView({ preserveVisibleState: true }).finally(function() {
            ethereumWalletUi.nativeSetupPollTimer = setTimeout(poll, 1500);
        });
    }
    ethereumWalletUi.nativeSetupPollTimer = setTimeout(poll, 500);
}

function ethereumLaunchWalletRequest(request) {
    return RS.invoke(ETHEREUM_UI_COMMANDS.launch, { request: request });
}

function ethereumSynchronize(options) {
    var propagateError = Boolean(options && options.propagateError === true);
    if (ethereumWalletUi.synchronizing) {
        return propagateError
            ? Promise.reject(new Error('ethereum_sync_in_progress'))
            : Promise.resolve();
    }
    var button = document.getElementById('ethereum-sync-btn');
    var status = document.getElementById('ethereum-sync-status');
    ethereumWalletUi.synchronizing = true;
    ethereumWalletUi.syncFeedback = 'Looking for the selected Ethereum service on Reticulum…';
    ethereumWalletUi.syncFeedbackError = false;
    button.disabled = true;
    status.textContent = ethereumWalletUi.syncFeedback;
    // No request data crosses this boundary. Rust selects the pinned profile
    // checkpoint, configured gateway, random identifiers, limits, and expiry.
    return RS.invoke(ETHEREUM_UI_COMMANDS.synchronize).then(function(result) {
        if (!result || (result.state !== 'queued' && result.state !== 'active') ||
            !Number.isSafeInteger(result.evidence_requests) || result.evidence_requests < 1 ||
            result.evidence_requests > 17 ||
            !Number.isSafeInteger(result.transaction_relays) || result.transaction_relays < 0 ||
            result.transaction_relays > 16) {
            throw new Error('invalid synchronization response');
        }
        var evidence = result.evidence_requests;
        var relays = result.transaction_relays;
        if (result.state === 'active') {
            ethereumWalletUi.syncFeedback =
                'Account checking is already in progress. Pending requests were resumed.';
        } else {
            ethereumWalletUi.syncFeedback = 'Account check requested: ' + evidence + ' evidence request' +
                (evidence === 1 ? '' : 's') + ' and ' + relays + ' transaction relay' +
                (relays === 1 ? '' : 's') + ' queued. Waiting for the Ethereum service…';
        }
        ethereumWalletUi.syncFeedbackError = false;
        status.textContent = ethereumWalletUi.syncFeedback;
        return loadEthereumWalletView({ preserveVisibleState: true });
    }).catch(function(error) {
        var reason = String(error || '');
        if (reason.includes('gateway_route') || reason.includes('reticulum')) {
            ethereumWalletUi.syncFeedback = 'Account check did not start because Ratspeak could not find a Reticulum route to the selected Ethereum service. Check your active interfaces or choose another service, then retry.';
        } else if (reason.includes('gateway_contact')) {
            ethereumWalletUi.syncFeedback = 'Account check could not start because the selected Ethereum service is not a valid Contact for this Ratspeak profile.';
        } else if (reason.includes('checkpoint')) {
            ethereumWalletUi.syncFeedback = 'Account check could not start because no approved checkpoint is ready.';
        } else if (reason.includes('gateway')) {
            ethereumWalletUi.syncFeedback = 'Account check could not start because the configured gateway is unavailable or changed.';
        } else if (reason.includes('identity') || reason.includes('profile')) {
            ethereumWalletUi.syncFeedback = 'Account check could not start because the active Ratspeak profile changed. Refresh and try again.';
        } else {
            ethereumWalletUi.syncFeedback = 'Account check could not start. Refresh the setup status and try again.';
        }
        ethereumWalletUi.syncFeedbackError = true;
        status.textContent = ethereumWalletUi.syncFeedback;
        if (propagateError) throw error;
    }).finally(function() {
        ethereumWalletUi.synchronizing = false;
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
    });
}

function ethereumManageWallet() {
    var state = ethereumNativeUiState(ethereumWalletUi.featureStatus);
    if (!state.enabled) return;
    var button = document.getElementById('ethereum-manage-wallet-btn');
    button.disabled = true;
    ethereumLaunchWalletRequest({ kind: 'manage_wallet' }).then(function() {
        if (ethereumWalletUi.featureStatus && ethereumWalletUi.featureStatus.platform === 'android') {
            ethereumStartNativeSetupPolling();
        } else if (typeof showToast === 'function') {
            showToast('Wallet setup complete', 'toast-success', 2400);
        }
    }).catch(function(error) {
        var reason = String(error || '');
        if (reason.includes('cancelled')) return;
        if (typeof showToast === 'function') {
            showToast(reason.includes('restore_failed')
                ? 'Wallet was not imported. Check the Secret Recovery Phrase and try again.'
                : reason.includes('secret_service')
                ? 'The Linux system keyring is unavailable. Unlock your keyring and try again.'
                : 'The Ethereum wallet action could not finish.', 'toast-error', 4500);
        }
    }).finally(function() {
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
        loadEthereumWalletView({ preserveVisibleState: true });
    });
}

function ethereumReviewPendingEvidence() {
    if (ethereumWalletUi.reviewingEvidence) return;
    var state = ethereumEvidenceReviewUiState(ethereumWalletUi.featureStatus);
    if (!state.enabled) return;
    var button = document.getElementById('ethereum-review-pending-evidence-btn');
    var status = document.getElementById('ethereum-sync-status');
    ethereumWalletUi.reviewingEvidence = true;
    button.disabled = true;
    // This command has no arguments. Native code owns the durable snapshots,
    // gateway/profile fence, and approve/deny choices.
    status.textContent = 'Opening a secure review of the requested download…';
    return RS.invoke(ETHEREUM_UI_COMMANDS.reviewPendingEvidence).then(function(result) {
        if (result && result.launched === true) {
            status.textContent = 'Native evidence review opened. Evidence remains untrusted pending local verification.';
        } else if (result && result.reviewed > 0) {
            status.textContent = 'Native review handled pending evidence. Local cryptographic verification is still required.';
        } else {
            status.textContent = 'Native evidence review did not resolve an item.';
        }
    }).catch(function() {
        status.textContent = 'Native evidence review is unavailable.';
    }).finally(function() {
        ethereumWalletUi.reviewingEvidence = false;
        loadEthereumWalletView({ preserveVisibleState: true });
    });
}

function ethereumReviewPendingCheckpoint() {
    var state = ethereumCheckpointReviewUiState(ethereumWalletUi.featureStatus);
    if (!state.enabled) return;
    var button = document.getElementById('ethereum-review-pending-checkpoint-btn');
    var status = document.getElementById('ethereum-checkpoint-status');
    button.disabled = true;
    // No candidate, root, bundle, provenance, or decision crosses this seam.
    // Native code resolves only an exact durable snapshot already in SQLite.
    status.textContent = 'Opening secure checkpoint review…';
    return RS.invoke(ETHEREUM_UI_COMMANDS.reviewPendingCheckpoint).then(function(result) {
        if (result && result.launched === true) {
            status.textContent = 'Native checkpoint review opened. Trust changes only after explicit native approval.';
        } else if (result && result.reviewed === 1 && result.approved === 1) {
            status.textContent = 'The explicitly approved Sepolia checkpoint was installed as local trust.';
        } else if (result && result.reviewed === 1 && result.denied === 1) {
            status.textContent = 'The pending Sepolia checkpoint was denied.';
        } else {
            status.textContent = 'Native checkpoint review did not resolve an item.';
        }
    }).catch(function() {
        status.textContent = 'No staged checkpoint is currently available for native review.';
    }).finally(function() {
        loadEthereumWalletView({ preserveVisibleState: true });
    });
}

function ethereumImportCheckpointFile() {
    var state = ethereumCheckpointFileImportUiState(ethereumWalletUi.featureStatus);
    if (!state.enabled) return;
    var button = document.getElementById('ethereum-import-checkpoint-file-btn');
    var status = document.getElementById('ethereum-checkpoint-status');
    button.disabled = true;
    // Native code selects and reads the document. The WebView supplies no
    // path, URI, bytes, checkpoint value, provenance, or approval decision.
    status.textContent = 'Opening the secure checkpoint picker…';
    return RS.invoke(ETHEREUM_UI_COMMANDS.importCheckpointFile).then(function(result) {
        if (result && result.launched === true) {
            status.textContent = 'Native checkpoint file picker opened. A valid selection will still require native review.';
            ethereumStartNativeSetupPolling();
        } else if (result && result.staged === true) {
            status.textContent = 'Checkpoint file validated. Opening secure review…';
            ethereumWalletUi.setupStatus = ethereumWalletUi.setupStatus || {};
            ethereumWalletUi.setupStatus.pending_checkpoint_review = true;
            ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
            return ethereumReviewPendingCheckpoint();
        } else if (result && result.cancelled === true) {
            status.textContent = 'Checkpoint file selection cancelled; no candidate was staged.';
        } else {
            status.textContent = 'Checkpoint file import did not stage a candidate.';
        }
    }).catch(function() {
        status.textContent = 'Checkpoint file import failed validation or is unavailable.';
    }).finally(function() {
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
    });
}

function ethereumConnectSepolia() {
    if (ethereumWalletUi.connectingSepolia) return;
    var button = document.getElementById('ethereum-connect-sepolia-btn');
    var status = document.getElementById('ethereum-checkpoint-status');
    ethereumWalletUi.connectingSepolia = true;
    ethereumWalletUi.checkpointFeedbackError = false;
    ethereumWalletUi.checkpointFeedback =
        'Checking ethPandaOps and ChainSafe as separate Sepolia sources…';
    button.disabled = true;
    status.textContent = ethereumWalletUi.checkpointFeedback;
    return RS.invoke(ETHEREUM_UI_COMMANDS.connectSepolia).then(function(result) {
        if (!result || result.state !== 'installed' || !Array.isArray(result.sources) ||
            result.sources.length !== 2) {
            throw new Error('invalid online checkpoint response');
        }
        ethereumWalletUi.checkpointFeedback = null;
        ethereumWalletUi.checkpointFeedbackError = false;
        status.textContent =
            'Sepolia checkpoint verified: ethPandaOps and ChainSafe agreed, and Ratspeak verified the light-client bootstrap locally.';
        return loadEthereumWalletView({ preserveVisibleState: true });
    }).catch(function(error) {
        var reason = String(error || '');
        ethereumWalletUi.checkpointFeedback = reason.includes('disagree')
            ? 'The configured checkpoint sources did not agree. Nothing was trusted; try again later or use Advanced offline setup.'
            : reason.includes('stale')
            ? 'The available checkpoint was too old. Nothing was trusted; try again later.'
            : reason.includes('profile') || reason.includes('identity')
            ? 'Your Ratspeak profile changed while Sepolia was being checked. Nothing was installed.'
            : 'Ratspeak could not verify Sepolia from both configured sources. Nothing was trusted; check internet access and try again.';
        ethereumWalletUi.checkpointFeedbackError = true;
        status.textContent = ethereumWalletUi.checkpointFeedback;
    }).finally(function() {
        ethereumWalletUi.connectingSepolia = false;
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
    });
}

function ethereumAddPublicServiceContact() {
    if (ethereumWalletUi.addingPublicService) return;
    var button = document.getElementById('ethereum-add-public-service-btn');
    var status = document.getElementById('ethereum-gateway-status');
    ethereumWalletUi.addingPublicService = true;
    ethereumWalletUi.gatewayFeedbackError = false;
    ethereumWalletUi.gatewayFeedback = 'Adding the configured public test service to Ratspeak Contacts…';
    button.disabled = true;
    status.textContent = ethereumWalletUi.gatewayFeedback;
    return RS.invoke(ETHEREUM_UI_COMMANDS.addPublicServiceContact).then(function(result) {
        if (!result || result.state !== 'added') throw new Error('invalid public service response');
        ethereumWalletUi.gatewayFeedback = null;
        ethereumWalletUi.gatewayFeedbackError = false;
        status.textContent = 'Public test service Contact added. Choose Ethereum service to review and select it.';
        return loadEthereumWalletView({ preserveVisibleState: true });
    }).catch(function() {
        ethereumWalletUi.gatewayFeedback =
            'The configured public test service could not be added. You can still add another operator in Ratspeak Contacts.';
        ethereumWalletUi.gatewayFeedbackError = true;
        status.textContent = ethereumWalletUi.gatewayFeedback;
    }).finally(function() {
        ethereumWalletUi.addingPublicService = false;
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
    });
}

function ethereumImportGatewayCard() {
    var status = document.getElementById('ethereum-gateway-status');
    ethereumWalletUi.gatewayFeedback = null;
    ethereumWalletUi.gatewayFeedbackError = false;
    document.getElementById('ethereum-import-gateway-card-btn').disabled = true;
    // Native code owns either the Linux Contacts chooser or Android's bounded
    // preview file picker. No destination, public key, path, or bytes are
    // supplied by this WebView.
    var pairingMethod = ethereumWalletUi.featureStatus &&
        ethereumWalletUi.featureStatus.native_gateway_pairing;
    status.textContent = pairingMethod === 'file'
        ? 'Opening Android’s service card picker…'
        : 'Opening your verified Ratspeak Contacts…';
    return RS.invoke(ETHEREUM_UI_COMMANDS.importGatewayCard).then(function(result) {
        if (result && result.launched === true) {
            status.textContent = pairingMethod === 'file'
                ? 'Service card picker opened. A valid card will still require secure review.'
                : 'Ethereum service chooser opened. A selection will require secure review.';
            ethereumStartNativeSetupPolling();
        } else if (result && result.staged) {
            status.textContent = 'Ethereum service Contact validated. Opening secure review…';
            ethereumWalletUi.setupStatus = ethereumWalletUi.setupStatus || {};
            ethereumWalletUi.setupStatus.pending_gateway_review = true;
            ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
            return ethereumReviewPendingGatewayCard();
        } else {
            status.textContent = 'Ethereum service selection cancelled; nothing changed.';
        }
    }).catch(function() {
        ethereumWalletUi.gatewayFeedback =
            'No valid Ethereum service Contact is available. Add a service in Ratspeak Contacts, then try again.';
        ethereumWalletUi.gatewayFeedbackError = true;
        status.textContent = ethereumWalletUi.gatewayFeedback;
    }).finally(function() { ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus); });
}

function ethereumReviewPendingGatewayCard() {
    var status = document.getElementById('ethereum-gateway-status');
    document.getElementById('ethereum-review-gateway-card-btn').disabled = true;
    // Native review supplies no destination, key, path, or decision argument.
    status.textContent = 'Opening secure Ethereum service review…';
    return RS.invoke(ETHEREUM_UI_COMMANDS.reviewPendingGatewayCard).then(function(result) {
        if (result && result.launched === true) status.textContent = 'Native Ethereum service review opened.';
        else if (result && result.approved) {
            ethereumWalletUi.gatewayFeedback = null;
            ethereumWalletUi.gatewayFeedbackError = false;
            status.textContent = 'Ethereum service selected for this Ratspeak profile.';
        }
        else if (result && result.denied) status.textContent = 'Ethereum service was not selected.';
        else status.textContent = 'Ethereum service review remains pending.';
    }).catch(function(error) {
        if (String(error || '').includes('gateway_contact')) {
            ethereumWalletUi.gatewayFeedback = 'Add this Ethereum service to Ratspeak Contacts before selecting it here.';
        } else {
            ethereumWalletUi.gatewayFeedback = 'Ethereum service review is unavailable or active work prevents replacement.';
        }
        ethereumWalletUi.gatewayFeedbackError = true;
        status.textContent = ethereumWalletUi.gatewayFeedback;
    }).finally(function() { loadEthereumWalletView({ preserveVisibleState: true }); });
}

function ethereumSubmitTransfer(event) {
    event.preventDefault();
    var error = document.getElementById('ethereum-transfer-error');
    error.textContent = '';
    var nativeState = ethereumNativeUiState(ethereumWalletUi.featureStatus);
    var parsed = ethereumRenderTransferSummary();
    if (!nativeState.enabled) {
        error.textContent = nativeState.message;
        return;
    }
    if (parsed.error) {
        error.textContent = parsed.error;
        return;
    }
    var button = document.getElementById('ethereum-review-native-btn');
    var signedLocally = false;
    button.disabled = true;
    error.textContent = 'Refreshing the verified account state before preparing the transfer…';
    // The account object rendered in the page may be minutes old by the time
    // the user presses Send.  Refresh the secret-free setup snapshot first;
    // native code independently enforces the same proof/freshness boundary.
    // `preserveVisibleState` keeps the last verified balance visible while
    // this refresh is in flight instead of flashing an unknown balance.
    loadEthereumWalletView({ preserveVisibleState: true }).then(function() {
        if (ethereumWalletUi.setupRefreshFailed) {
            throw new Error('ethereum_setup_refresh_failed');
        }
        if (!ethereumWalletUi.account ||
            ethereumWalletUi.account.assurance !== 'current_verified') {
            throw new Error('ethereum_transfer_requires_current_proof');
        }
        error.textContent = 'Opening secure transaction review…';
        // The Linux native dialog runs a synchronous, secret-bearing GTK
        // ceremony. Suspend WebView IPC polling so queued status calls cannot
        // starve password-entry events or make the app appear unresponsive.
        ethereumSetNativeCeremonyActive(true);
        return ethereumLaunchWalletRequest(parsed.request);
    }).then(function(result) {
        ethereumSetNativeCeremonyActive(false);
        if (ethereumWalletUi.featureStatus &&
            ethereumWalletUi.featureStatus.platform === 'android') {
            error.textContent = 'Native transaction review opened. Ratspeak will show the transaction hash only after Android confirms that signing finished.';
            return ethereumLoadLatestTransaction();
        }
        if (!result || typeof result.operation_id !== 'string' ||
            !/^[0-9a-f]{32}$/.test(result.operation_id)) {
            throw new Error('ethereum_native_signing_result_invalid');
        }
        var signedTxHash = ethereumNormalizeTransactionHash(result.tx_hash);
        if (!signedTxHash) {
            throw new Error('ethereum_native_signing_result_invalid');
        }
        signedLocally = true;
        error.textContent = 'Signed locally. Ratspeak is preparing delivery to the selected Ethereum service; exact finalized receipt evidence is still required for confirmation.';
        return ethereumLoadLatestTransaction().then(function(transaction) {
            // Linux native review resolves only after the exact transaction is
            // durably signed. Schedule relay and receipt work immediately so
            // the user never has to press account refresh after signing.
            if (!transaction || ethereumNormalizeTransactionHash(transaction.tx_hash) !== signedTxHash) {
                throw new Error('ethereum_signed_transaction_correlation_failed');
            }
            if (transaction.assurance === 'signed_unconfirmed') {
                return ethereumSynchronize({ propagateError: true });
            }
        });
    }).catch(function(reason) {
        ethereumSetNativeCeremonyActive(false);
        var message = String(reason || '');
        if (signedLocally) {
            error.textContent = 'Signed locally, but Ratspeak could not schedule delivery yet. The transaction remains safely stored on this device; retry the account check to send it.';
        } else if (message.includes('ethereum_transfer_cancelled')) {
            error.textContent = 'Transaction signing was cancelled. Nothing was signed or sent.';
        } else if (message.includes('ethereum_wallet_password_invalid')) {
            error.textContent = 'The wallet password is incorrect. Nothing was signed or sent; try again.';
        } else if (message.includes('ethereum_transfer_expired')) {
            error.textContent = 'The secure confirmation expired before signing finished. Nothing was sent; review the transaction again.';
        } else if (message.includes('requires_current_proof') ||
            message.includes('stale') || message.includes('proof')) {
            error.textContent = 'Your verified balance and nonce are too old to prepare this transfer safely. Check your account again, then retry.';
        } else if (message.includes('setup_refresh_failed')) {
            error.textContent = 'Ratspeak could not refresh the verified account state. Your last verified balance remains shown; retry the account check before sending.';
        } else {
            error.textContent = 'The native wallet could not prepare this transfer. Your displayed balance was not changed. Check your account and try again.';
        }
    }).finally(function() {
        ethereumApplyFeatureStatus(ethereumWalletUi.featureStatus);
    });
}

function ethereumBindWalletUi() {
    if (ethereumWalletUi.bound) return;
    ethereumWalletUi.bound = true;
    document.getElementById('ethereum-refresh-btn').addEventListener('click', function() {
        ethereumWalletUi.syncFeedback = null;
        ethereumWalletUi.syncFeedbackError = false;
        ethereumWalletUi.checkpointFeedback = null;
        ethereumWalletUi.checkpointFeedbackError = false;
        ethereumWalletUi.gatewayFeedback = null;
        ethereumWalletUi.gatewayFeedbackError = false;
        loadEthereumWalletView({ preserveVisibleState: true });
    });
    document.getElementById('ethereum-change-checkpoint-btn').addEventListener('click', function() {
        ethereumConnectSepolia();
    });
    document.getElementById('ethereum-connect-sepolia-btn').addEventListener('click', ethereumConnectSepolia);
    document.getElementById('ethereum-sync-btn').addEventListener('click', ethereumSynchronize);
    document.getElementById('ethereum-manage-wallet-btn').addEventListener('click', ethereumManageWallet);
    document.getElementById('ethereum-review-pending-evidence-btn').addEventListener('click', ethereumReviewPendingEvidence);
    document.getElementById('ethereum-review-pending-checkpoint-btn').addEventListener('click', ethereumReviewPendingCheckpoint);
    document.getElementById('ethereum-import-checkpoint-file-btn').addEventListener('click', ethereumImportCheckpointFile);
    document.getElementById('ethereum-add-public-service-btn').addEventListener('click', ethereumAddPublicServiceContact);
    document.getElementById('ethereum-import-gateway-card-btn').addEventListener('click', ethereumImportGatewayCard);
    document.getElementById('ethereum-open-contacts-btn').addEventListener('click', function() {
        if (typeof switchView === 'function') switchView('contacts');
    });
    document.getElementById('ethereum-review-gateway-card-btn').addEventListener('click', ethereumReviewPendingGatewayCard);
    document.getElementById('ethereum-update-transaction-status-btn').addEventListener('click', ethereumUpdateTransactionStatus);
    if (typeof RS !== 'undefined' && RS.listen) {
        RS.listen('ethereum_state_updated', function() {
            if (typeof currentView !== 'string' || currentView !== 'ethereum' ||
                ethereumWalletUi.reviewingEvidence) return;
            // The event carries no protocol data.  Refresh the coarse,
            // secret-free Ethereum state so account/evidence progress appears
            // in this tab without creating a generic chat notification.
            loadEthereumWalletView({ preserveVisibleState: true });
        });
        RS.listen('ethereum_bulk_evidence_review_ready', function() {
            if (typeof currentView !== 'string' || currentView !== 'ethereum' ||
                ethereumWalletUi.reviewingEvidence) return;
            loadEthereumWalletView({ preserveVisibleState: true }).then(function() {
                if (ethereumWalletUi.setupStatus &&
                    ethereumWalletUi.setupStatus.pending_evidence_review === true) {
                    ethereumReviewPendingEvidence();
                }
            });
        });
    }
    document.getElementById('ethereum-transfer-form').addEventListener('submit', ethereumSubmitTransfer);
    ['ethereum-recipient', 'ethereum-value-eth', 'ethereum-max-fee-gwei',
        'ethereum-priority-fee-gwei'].forEach(function(id) {
        document.getElementById(id).addEventListener('input', ethereumRenderTransferSummary);
    });
    document.getElementById('ethereum-address').addEventListener('click', function(event) {
        var value = event.currentTarget.dataset.copyValue;
        if (!value) return;
        RS.copyText(value).then(function(copied) {
            if (copied && typeof showToast === 'function') {
                showToast('Ethereum address copied', 'toast-success', 1800);
            }
        });
    });
    document.getElementById('ethereum-copy-checkpoint-root-btn').addEventListener('click', function() {
        var root = document.getElementById('ethereum-checkpoint-root').textContent;
        if (!/^0x[0-9a-fA-F]{64}$/.test(root)) return;
        RS.copyText(root).then(function(copied) {
            if (copied && typeof showToast === 'function') {
                showToast('Checkpoint root copied', 'toast-success', 1800);
            }
        });
    });
}

function ethereumInitWalletSurface() {
    ethereumBindWalletUi();
    loadEthereumWalletView();
}

ethereumInitWalletSurface();
