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
var scheduledTimers = [];
var nextTimerId = 1;
var windowStub = {
    RS: {},
    matchMedia: function() { return { matches: false }; },
    setTimeout: function(callback, delay) {
        var timer = { id: nextTimerId++, callback: callback, delay: delay, active: true };
        scheduledTimers.push(timer);
        return timer.id;
    },
    clearTimeout: function(id) {
        scheduledTimers.forEach(function(timer) {
            if (timer.id === id) timer.active = false;
        });
    },
};

function runNextTimer() {
    while (scheduledTimers.length) {
        var timer = scheduledTimers.shift();
        if (timer.active) {
            timer.callback();
            return timer.delay;
        }
    }
    return null;
}
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
assert(adapter, "Conway's Game of Life adapter must register under the LRGP app_id");
assert.strictEqual(adapter.displayName, "Conway's Game of Life");
assert.strictEqual(adapter.icon, '\uD83D\uDC7E');
assert.strictEqual(adapter.participantLabel, 'with');
assert.strictEqual(adapter.participantPickerLabel, 'Contact');
assert.strictEqual(adapter.challengeLabel, 'invitation');
assert.strictEqual(adapter.challengeVerb, 'invite');
assert.strictEqual(adapter.boardSelector, '.life-board');
assert.strictEqual(typeof adapter.onSessionDelta, 'function');
assert.strictEqual(typeof adapter.restartPayload, 'function');
assert.strictEqual(typeof adapter.canRestart, 'function');
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

function boardHex(liveIndices) {
    var bytes = new Array(32).fill(0);
    liveIndices.forEach(function(index) {
        bytes[Math.floor(index / 8)] |= 0x80 >> (index % 8);
    });
    return bytes.map(function(byte) { return byte.toString(16).padStart(2, '0'); }).join('');
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
assert(pendingHtml.includes('Life Spark received · accept to evolve 24 generations'));
assert.deepStrictEqual(
    Array.from(adapter.detailChips(session())),
    ['Generation 7', '4 live cells']
);

var beforeStep = session();
beforeStep.metadata.board = '80' + '00'.repeat(31);
var afterStep = session({ status: 'active' });
afterStep.metadata.parent_board = beforeStep.metadata.board;
afterStep.metadata.board = '00'.repeat(32);
afterStep.metadata.generation = 31;
adapter.onSessionDelta(afterStep, beforeStep);
var transitionHtml = adapter.renderBoard(afterStep, viewContext());
assert(transitionHtml.includes('<span class="life-generation">Generation 7</span>'),
    'an arriving run must first render the complete previous generation');
assert(transitionHtml.includes('<span class="life-live-count">1 live</span>'));
assert(transitionHtml.includes('life-cell alive" data-cell-index="0"'),
    'the previous frame must remain intact during the readable hold');
assert(transitionHtml.includes('life-cell" data-cell-index="1"'));
assert(!transitionHtml.includes('life-born') && !transitionHtml.includes('life-died'),
    'Life generations must switch discretely instead of inventing cell motion');

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

var completed = session({
    game_id: 'life-completed',
    status: 'completed',
    initiator: 'them',
});
completed.metadata.generation = 31;
completed.metadata.holder = 'me';
completed.metadata.world_id = '0123456789abcdef';
// A horizontal blinker crossing the toroidal edge returns to the same phase
// after the even 24-generation handoff, while every odd frame is vertical.
completed.metadata.parent_board = boardHex([128, 129, 143]);
completed.metadata.board = completed.metadata.parent_board;
var completedHtml = adapter.renderBoard(completed, viewContext());
assert(completedHtml.includes('You received the Life Torch'));
assert(completedHtml.includes('id="games-life-replay-btn"'));
assert(completedHtml.includes('id="games-life-final-btn"'));
assert(completedHtml.includes('id="games-life-loop-btn"'));
assert(completedHtml.includes('aria-pressed="false"'));
assert(completedHtml.includes('aria-label="Replay 24 generations"'));
assert.strictEqual(adapter.canRestart(completed), true);
assert.strictEqual(adapter.restartLabel(completed), 'Continue evolution');
assert.deepStrictEqual(
    JSON.parse(JSON.stringify(adapter.restartPayload(completed))),
    {
        b: completed.metadata.board,
        g: 31,
        w: '0123456789abcdef',
    },
    'the holder must continue the exact world head through a fresh generic challenge'
);
var handedOff = session({ status: 'completed', initiator: 'me' });
handedOff.metadata.holder = 'them';
assert.strictEqual(adapter.canRestart(handedOff), false,
    'only the current holder may continue a completed evolution');
assert.strictEqual(adapter.restartPayload(handedOff), null);

var successor = JSON.parse(JSON.stringify(completed));
successor.game_id = 'successor-session';
successor.status = 'pending';
assert.strictEqual(adapter.canRestart(completed, [completed, successor]), false,
    'a world head with a pending successor must not be continued twice');
assert.strictEqual(adapter.restartPayload(completed, [completed, successor]), null,
    'a consumed world head must not create another continuation payload');
assert.strictEqual(adapter.statusClass(completed), 'status-complete',
    'successful handoffs must not inherit a competitive loss style');

function fakeClassList() {
    var values = {};
    return {
        add: function(name) { values[name] = true; },
        remove: function(name) { delete values[name]; },
        contains: function(name) { return !!values[name]; },
    };
}

var playbackCells = Array.from({ length: 256 }, function(_, index) {
    var attributes = { 'data-cell-index': String(index) };
    return {
        classList: fakeClassList(),
        getAttribute: function(name) { return attributes[name] || null; },
        setAttribute: function(name, value) { attributes[name] = String(value); },
    };
});
var boardAttributes = { 'data-life-session': completed.game_id };
var playbackBoard = {
    getAttribute: function(name) { return boardAttributes[name] || null; },
    setAttribute: function(name, value) { boardAttributes[name] = String(value); },
    querySelectorAll: function() { return playbackCells; },
};
var generationLabel = { textContent: '' };
var liveCountLabel = { textContent: '' };
var playbackStatus = { textContent: '' };
function fakeButton() {
    var attributes = {};
    return {
        textContent: '',
        addEventListener: function(name, handler) { this[name] = handler; },
        getAttribute: function(name) { return attributes[name] || null; },
        setAttribute: function(name, value) { attributes[name] = String(value); },
    };
}
var replayButton = fakeButton();
var finalButton = fakeButton();
var loopButton = fakeButton();
var playbackRoot = {
    querySelector: function(selector) {
        if (selector === '.life-board') return playbackBoard;
        if (selector === '.life-generation') return generationLabel;
        if (selector === '.life-live-count') return liveCountLabel;
        if (selector === '#games-life-replay-btn') return replayButton;
        if (selector === '#games-life-final-btn') return finalButton;
        if (selector === '#games-life-loop-btn') return loopButton;
        if (selector === '#games-life-playback-status') return playbackStatus;
        return null;
    },
};
adapter.bindBoard(completed, { root: playbackRoot });
replayButton.click();
assert.strictEqual(generationLabel.textContent, 'Generation 7');
assert.strictEqual(liveCountLabel.textContent, '3 live');
assert(playbackCells[128].classList.contains('alive'));
assert(playbackCells[129].classList.contains('alive'));
assert(playbackCells[143].classList.contains('alive'));
assert(playbackStatus.textContent.includes('Playing generations 7 through 31'));
var replayElapsed = 0;
replayElapsed += runNextTimer();
assert.strictEqual(generationLabel.textContent, 'Generation 8');
assert(playbackCells[112].classList.contains('alive'),
    'the first step must wrap the edge blinker into row 8, column 1');
assert(playbackCells[128].classList.contains('alive'));
assert(playbackCells[144].classList.contains('alive'));
assert(!playbackCells[129].classList.contains('alive'));
assert(!playbackCells[143].classList.contains('alive'));
for (var frame = 1; frame < 24; frame++) replayElapsed += runNextTimer();
assert.strictEqual(replayElapsed, 7200, '24 generations at 300 ms must produce a 7.2 second run');
assert.strictEqual(generationLabel.textContent, 'Generation 31');
assert.strictEqual(liveCountLabel.textContent, '3 live');
assert(playbackCells[128].classList.contains('alive'));
assert(playbackCells[129].classList.contains('alive'));
assert(playbackCells[143].classList.contains('alive'));
assert(playbackStatus.textContent.includes('Evolution complete at generation 31'));
assert.strictEqual(runNextTimer(), null, 'a one-shot replay must stop on the canonical frame');

loopButton.click();
assert.strictEqual(loopButton.getAttribute('aria-pressed'), 'true');
assert.strictEqual(generationLabel.textContent, 'Generation 7');
finalButton.click();
assert.strictEqual(loopButton.getAttribute('aria-pressed'), 'false');
assert.strictEqual(generationLabel.textContent, 'Generation 31',
    'showing the final frame must stop a loop and restore the canonical generation');
assert(playbackStatus.textContent.includes('Showing final generation 31'));

console.log('Conway Life view tests passed');
