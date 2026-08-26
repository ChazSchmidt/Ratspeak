#!/usr/bin/env node
'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var registrySource = fs.readFileSync(
    path.join(__dirname, '..', 'static', 'js', 'game_registry.js'),
    'utf8'
);
var viewSource = fs.readFileSync(
    path.join(__dirname, '..', 'static', 'js', 'conway_life_view.js'),
    'utf8'
);
var windowStub = { RS: {} };
var context = {
    window: windowStub,
    Object: Object,
    TypeError: TypeError,
    Error: Error,
};
vm.createContext(context);
vm.runInContext(registrySource, context, { filename: 'game_registry.js' });
vm.runInContext(viewSource, context, { filename: 'conway_life_view.js' });

var adapter = windowStub.RS.games.views.get('conway_life');
assert(adapter, 'Life Torch adapter must register under the LRGP app_id');
assert.strictEqual(adapter.displayName, 'Life Torch');
assert.strictEqual(adapter.boardSelector, '.life-board');
assert.deepStrictEqual(Array.from(adapter.actions), [
    'challenge', 'accept', 'move', 'decline', 'error'
]);

function session(overrides) {
    var base = {
        game_id: 'life-test',
        app_id: 'conway_life',
        status: 'pending',
        identity_id: 'me',
        my_lxmf_hash: 'me',
        contact_hash: 'them',
        initiator: 'them',
        metadata: {
            board: '8180' + '00'.repeat(29) + '01',
            generation: 7,
            holder: 'them',
            claimant: '',
            awaiting_award: false,
        },
    };
    Object.keys(overrides || {}).forEach(function(key) { base[key] = overrides[key]; });
    return base;
}

function viewContext() {
    return {
        isMe: function(hash) { return hash === 'me'; },
        contactName: function() { return '<Sender>'; },
    };
}

var pendingHtml = adapter.renderBoard(session(), viewContext());
assert.strictEqual((pendingHtml.match(/role="gridcell"/g) || []).length, 256,
    'the view must render all 256 cells');
assert.strictEqual((pendingHtml.match(/role="row"/g) || []).length, 16,
    'the ARIA grid must group its cells into 16 semantic rows');
assert.strictEqual((pendingHtml.match(/life-cell alive/g) || []).length, 4,
    'row-major MSB-first bits must drive the live cells');
assert(pendingHtml.includes('aria-rowindex="1" aria-colindex="1"'));
assert(pendingHtml.includes('aria-rowindex="16" aria-colindex="16"'));
assert(pendingHtml.includes('Row 1, column 1: alive'));
assert(pendingHtml.includes('Row 1, column 2: dead'));
assert(pendingHtml.includes('Life Spark received · accept to advance one generation'));
assert.deepStrictEqual(
    Array.from(adapter.detailChips(session())),
    ['Generation 7', '4 live cells']
);

var malformed = session();
malformed.metadata.board = 'not-a-board';
var malformedHtml = adapter.renderBoard(malformed, viewContext());
assert.strictEqual((malformedHtml.match(/life-cell alive/g) || []).length, 0,
    'malformed persisted boards must render as empty, never partial state');

var initiator = session({
    status: 'active',
    initiator: 'me',
    contact_hash: 'them',
});
initiator.metadata.holder = 'me';
initiator.metadata.claimant = 'them';
initiator.metadata.awaiting_award = true;
assert.strictEqual(
    adapter.activeStatusText(initiator, viewContext()),
    'Claim verified · hand off the torch'
);
assert(adapter.renderActiveControls(initiator).includes('id="games-life-award-btn"'));

var boundId = '';
var sent = null;
adapter.bindControls(initiator, {
    bindButton: function(id, handler) {
        boundId = id;
        handler();
    },
    sendAction: function(action, payload) {
        sent = { action: action, payload: payload };
    },
});
assert.strictEqual(boundId, 'games-life-award-btn');
assert.deepStrictEqual(JSON.parse(JSON.stringify(sent)), { action: 'move', payload: {} },
    'the handoff control must use the generic LRGP move action');

var claimant = session({ status: 'active' });
claimant.metadata.board = '00'.repeat(32);
claimant.metadata.generation = 8;
claimant.metadata.claimant = 'me';
claimant.metadata.awaiting_award = true;
assert.strictEqual(
    adapter.activeStatusText(claimant, viewContext()),
    'Waiting for <Sender> to hand off the torch'
);
assert(adapter.renderActiveControls(claimant).includes('Waiting for the sender'));
var claimantBound = false;
adapter.bindControls(claimant, {
    bindButton: function() { claimantBound = true; },
    sendAction: function() { claimantBound = true; },
});
assert.strictEqual(claimantBound, false, 'the claimant must not be able to award itself');

var completed = session({ status: 'completed', initiator: 'them' });
completed.metadata.generation = 8;
completed.metadata.holder = 'me';
assert(adapter.renderBoard(completed, viewContext()).includes('You received the Life Torch'));
assert.strictEqual(adapter.statusClass(completed), 'status-complete',
    'successful handoffs must not inherit a competitive loss style');

console.log('Conway Life view tests passed');
