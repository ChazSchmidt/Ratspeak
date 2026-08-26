#!/usr/bin/env node
'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var source = fs.readFileSync(
    path.join(__dirname, '..', 'static', 'js', 'games_tab.js'),
    'utf8'
);
source = source.replace(
    '    function _initGameEvents() {',
    '    window.__gameContinuationTest = {' +
        ' startNewGame: startNewGame, beginSessionAction: _beginSessionAction };\n\n' +
        '    function _initGameEvents() {'
);

var views = {};
var invocations = [];
var context = {
    Uint8Array: Uint8Array,
    console: console,
    crypto: {
        getRandomValues: function(bytes) {
            for (var i = 0; i < bytes.length; i++) bytes[i] = i;
            return bytes;
        },
    },
    document: {
        readyState: 'loading',
        addEventListener: function() {},
        getElementById: function() { return null; },
        querySelector: function() { return null; },
        querySelectorAll: function() { return []; },
    },
    RS: {
        games: {
            state: {
                value: function(session, key, fallback) {
                    return session && session.metadata && session.metadata[key] !== undefined
                        ? session.metadata[key]
                        : fallback;
                },
            },
            views: {
                get: function(id) { return views[id] || null; },
                has: function(id) { return !!views[id]; },
                register: function(id, adapter) { views[id] = adapter; },
            },
        },
        invoke: function(command) {
            invocations.push(command);
            if (command === 'send_game_action') {
                return Promise.resolve({ ok: true, session_id: 'new-session' });
            }
            if (command === 'get_all_game_sessions') {
                return Promise.reject(new Error('transient refresh failure'));
            }
            return Promise.resolve(null);
        },
    },
};
context.window = context;
vm.createContext(context);
vm.runInContext(source, context, { filename: 'games_tab.js' });

var hook = context.__gameContinuationTest;
var restartActionId = 'restart:completed-session';
assert.strictEqual(hook.beginSessionAction(restartActionId), true);
hook.startNewGame('conway_life', 'friend', {}, restartActionId);

setImmediate(function() {
    setImmediate(function() {
        assert.deepStrictEqual(invocations, ['send_game_action', 'get_all_game_sessions']);
        assert.strictEqual(
            hook.beginSessionAction(restartActionId),
            true,
            'a failed refresh must release the continuation lock'
        );
        console.log('Game continuation tests passed');
    });
});
