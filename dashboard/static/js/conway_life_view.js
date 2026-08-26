(function(global) {
    'use strict';

    var RS = global.RS = global.RS || {};
    if (!RS.games || !RS.games.views) {
        throw new Error('Game view registry must load before conway_life_view.js');
    }

    var APP_ID = 'conway_life';
    var BOARD_SIDE = 16;
    var BOARD_BYTES = 32;
    var EMPTY_BOARD = new Array(BOARD_BYTES).fill(0);

    function _meta(session, key, fallback) {
        return RS.games.state.value(session, key, fallback);
    }

    function _board(session) {
        var hex = _meta(session, 'board', '');
        if (typeof hex !== 'string' || hex.length !== BOARD_BYTES * 2 || /[^0-9a-f]/.test(hex)) {
            return EMPTY_BOARD;
        }
        var bytes = [];
        for (var i = 0; i < BOARD_BYTES; i++) {
            bytes.push(parseInt(hex.slice(i * 2, i * 2 + 2), 16));
        }
        return bytes;
    }

    function _isAlive(board, index) {
        return (board[Math.floor(index / 8)] & (0x80 >> (index % 8))) !== 0;
    }

    function _liveCount(board) {
        var count = 0;
        for (var index = 0; index < BOARD_SIDE * BOARD_SIDE; index++) {
            if (_isAlive(board, index)) count += 1;
        }
        return count;
    }

    function _localIdentity(session) {
        return session.my_lxmf_hash || session.identity_id || '';
    }

    function _isLocalInitiator(session) {
        return !!_localIdentity(session) && _localIdentity(session) ===
            (session.initiator || session.challenger || _meta(session, 'initiator', ''));
    }

    function _renderBoard(session, context) {
        var board = _board(session);
        var generation = parseInt(_meta(session, 'generation', 0), 10) || 0;
        var liveCount = _liveCount(board);
        var html = '<div class="life-board-wrap">' +
            '<div class="life-summary">' +
                '<span>Generation ' + generation + '</span>' +
                '<span>' + liveCount + ' live</span>' +
            '</div>' +
            '<div class="life-board" role="grid" aria-label="Conway Life generation ' +
                generation + '" aria-rowcount="16" aria-colcount="16">';

        for (var row = 0; row < BOARD_SIDE; row++) {
            html += '<span class="life-row" role="row">';
            for (var column = 0; column < BOARD_SIDE; column++) {
                var index = row * BOARD_SIDE + column;
                var alive = _isAlive(board, index);
                html += '<span class="life-cell' + (alive ? ' alive' : '') +
                    '" role="gridcell" aria-rowindex="' + (row + 1) +
                    '" aria-colindex="' + (column + 1) +
                    '" aria-label="Row ' + (row + 1) + ', column ' + (column + 1) +
                    ': ' + (alive ? 'alive' : 'dead') + '"></span>';
            }
            html += '</span>';
        }
        html += '</div>';

        if (session.status === 'pending') {
            var incoming = !(context && context.isMe && context.isMe(
                session.initiator || session.challenger || _meta(session, 'initiator', '')
            ));
            html += '<div class="life-state-note">' +
                (incoming ? 'Life Spark received · accept to advance one generation' :
                    'Life Spark sent · waiting for a claim') +
            '</div>';
        } else if (session.status === 'active') {
            html += '<div class="life-state-note">' +
                (_isLocalInitiator(session) ? 'Generation verified · ready to hand off' :
                    'Generation submitted · waiting for the handoff') +
            '</div>';
        } else if (session.status === 'completed') {
            html += '<div class="life-state-note complete">' +
                (_meta(session, 'holder', '') === _localIdentity(session) ?
                    'You received the Life Torch' : 'Life Torch handed off') +
            '</div>';
        }
        html += '</div>';
        return html;
    }

    function _activeStatusText(session, context) {
        if (_isLocalInitiator(session)) return 'Claim verified · hand off the torch';
        var initiator = session.initiator || session.challenger || '';
        var name = context && context.contactName ? context.contactName(initiator) : 'Sender';
        return 'Waiting for ' + name + ' to hand off the torch';
    }

    function _detailChips(session) {
        var board = _board(session);
        var generation = parseInt(_meta(session, 'generation', 0), 10) || 0;
        return ['Generation ' + generation, _liveCount(board) + ' live cells'];
    }

    function _statusClass(session) {
        return session.status === 'completed' ? 'status-complete' : '';
    }

    function _renderActiveControls(session) {
        if (_isLocalInitiator(session)) {
            return '<button class="nr-btn games-ctrl-accept" id="games-life-award-btn">' +
                'Hand off torch</button>';
        }
        return '<span class="games-ctrl-waiting">Waiting for the sender to hand off the torch...</span>';
    }

    function _bindControls(session, controls) {
        if (!_isLocalInitiator(session) || !controls) return;
        controls.bindButton('games-life-award-btn', function() {
            controls.sendAction('move', {});
        });
    }

    if (!RS.games.views.has(APP_ID)) {
        RS.games.views.register(APP_ID, {
            displayName: 'Life Torch',
            icon: '\uD83E\uDDEC',
            themeClass: 'games-theme-life',
            boardSelector: '.life-board',
            actions: ['challenge', 'accept', 'move', 'decline', 'error'],
            renderBoard: _renderBoard,
            bindBoard: function() {},
            activeStatusText: _activeStatusText,
            statusClass: _statusClass,
            detailChips: _detailChips,
            renderActiveControls: _renderActiveControls,
            bindControls: _bindControls,
        });
    }
})(window);
