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
    var GENERATIONS_PER_HANDOFF = 24;
    var FRAME_HOLD_MS = 300;
    var FINAL_FRAME_HOLD_MS = 900;
    var _autoPlay = Object.create(null);
    var _looping = Object.create(null);
    var _playbackTimers = Object.create(null);
    var _playbackFrame = Object.create(null);
    var _seenGenerations = Object.create(null);

    function _meta(session, key, fallback) {
        return RS.games.state.value(session, key, fallback);
    }

    function _decodeBoard(hex) {
        if (typeof hex !== 'string' || hex.length !== BOARD_BYTES * 2 || /[^0-9a-f]/.test(hex)) {
            return null;
        }
        var bytes = [];
        for (var i = 0; i < BOARD_BYTES; i++) {
            bytes.push(parseInt(hex.slice(i * 2, i * 2 + 2), 16));
        }
        return bytes;
    }

    function _board(session) {
        return _decodeBoard(_meta(session, 'board', '')) || EMPTY_BOARD;
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

    function _sameBoard(left, right) {
        for (var i = 0; i < BOARD_BYTES; i++) {
            if (left[i] !== right[i]) return false;
        }
        return true;
    }

    function _nextGeneration(board) {
        var next = new Array(BOARD_BYTES).fill(0);
        for (var row = 0; row < BOARD_SIDE; row++) {
            for (var column = 0; column < BOARD_SIDE; column++) {
                var neighbors = 0;
                for (var rowDelta = -1; rowDelta <= 1; rowDelta++) {
                    for (var columnDelta = -1; columnDelta <= 1; columnDelta++) {
                        if (rowDelta === 0 && columnDelta === 0) continue;
                        var neighborRow = (row + rowDelta + BOARD_SIDE) % BOARD_SIDE;
                        var neighborColumn = (column + columnDelta + BOARD_SIDE) % BOARD_SIDE;
                        neighbors += _isAlive(
                            board,
                            neighborRow * BOARD_SIDE + neighborColumn
                        ) ? 1 : 0;
                    }
                }
                var index = row * BOARD_SIDE + column;
                if (neighbors === 3 || (_isAlive(board, index) && neighbors === 2)) {
                    next[Math.floor(index / 8)] |= 0x80 >> (index % 8);
                }
            }
        }
        return next;
    }

    function _playbackFrames(session) {
        var parent = _decodeBoard(_meta(session, 'parent_board', ''));
        var current = _decodeBoard(_meta(session, 'board', ''));
        var generation = parseInt(_meta(session, 'generation', 0), 10) || 0;
        if (!parent || !current || generation < GENERATIONS_PER_HANDOFF) return null;

        var frames = [{
            board: parent,
            generation: generation - GENERATIONS_PER_HANDOFF,
        }];
        var board = parent;
        for (var offset = 1; offset <= GENERATIONS_PER_HANDOFF; offset++) {
            board = _nextGeneration(board);
            frames.push({
                board: board,
                generation: generation - GENERATIONS_PER_HANDOFF + offset,
            });
        }
        return _sameBoard(board, current) ? frames : null;
    }

    function _prefersReducedMotion() {
        return !!(global.matchMedia && global.matchMedia('(prefers-reduced-motion: reduce)').matches);
    }

    function _onSessionDelta(record, previous) {
        if (!record || !record.game_id || !previous) return;
        var generation = parseInt(_meta(record, 'generation', 0), 10) || 0;
        var previousGeneration = parseInt(_meta(previous, 'generation', 0), 10) || 0;
        var frames = _playbackFrames(record);
        if (!frames || generation !== previousGeneration + GENERATIONS_PER_HANDOFF ||
                !_sameBoard(frames[0].board, _board(previous))) return;
        _looping[record.game_id] = false;
        _clearPlaybackTimer(record.game_id);
        delete _playbackFrame[record.game_id];
        _autoPlay[record.game_id] = true;
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
        var frames = _playbackFrames(session);
        var seenGeneration = _seenGenerations[session.game_id];
        if (seenGeneration !== undefined &&
                generation === seenGeneration + GENERATIONS_PER_HANDOFF && frames) {
            _autoPlay[session.game_id] = true;
        }
        var activeFrame = _playbackFrame[session.game_id];
        var autoPlaying = !!(_autoPlay[session.game_id] && frames && !_prefersReducedMotion());
        var displayedBoard = activeFrame ? activeFrame.board : (autoPlaying ? frames[0].board : board);
        var displayedGeneration = activeFrame
            ? activeFrame.generation
            : (autoPlaying ? frames[0].generation : generation);
        var liveCount = _liveCount(displayedBoard);
        var html = '<div class="life-board-wrap">' +
            '<div class="life-summary">' +
                '<span class="life-generation">Generation ' + displayedGeneration + '</span>' +
                '<span class="life-live-count">' + liveCount + ' live</span>' +
            '</div>' +
            '<div class="life-board" role="grid" aria-label="Conway Life generation ' +
                displayedGeneration + '" aria-rowcount="16" aria-colcount="16" data-generation="' +
                displayedGeneration + '" data-life-session="' + session.game_id + '">';

        for (var row = 0; row < BOARD_SIDE; row++) {
            html += '<span class="life-row" role="row">';
            for (var column = 0; column < BOARD_SIDE; column++) {
                var index = row * BOARD_SIDE + column;
                var alive = _isAlive(displayedBoard, index);
                html += '<span class="life-cell' + (alive ? ' alive' : '') +
                    '" data-cell-index="' + index +
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
                (incoming ? 'Life Torch invitation received · accept to evolve 24 generations' :
                    'Life Torch invitation sent · waiting for a response') +
            '</div>';
        } else if (session.status === 'active') {
            html += '<div class="life-state-note">' +
                (_isLocalInitiator(session) ? 'Evolution verified · ready to pass the Life Torch' :
                    'Evolution submitted · waiting for the Life Torch') +
            '</div>';
        } else if (session.status === 'completed') {
            html += '<div class="life-state-note complete">' +
                (_meta(session, 'holder', '') === _localIdentity(session) ?
                    'You received the Life Torch' : 'Life Torch passed') +
            '</div>';
        }
        if (frames) {
            var looping = !!_looping[session.game_id];
            html += '<div class="life-playback" aria-label="Generation playback controls">' +
                '<button class="nr-btn nr-btn-ghost nr-btn-sm" id="games-life-replay-btn" type="button" aria-label="Replay 24 generations">Replay evolution</button>' +
                '<button class="nr-btn nr-btn-ghost nr-btn-sm" id="games-life-final-btn" type="button">Show final</button>' +
                '<button class="nr-btn nr-btn-ghost nr-btn-sm" id="games-life-loop-btn" type="button" aria-pressed="' + looping + '">' +
                    (looping ? 'Stop loop' : 'Loop') +
                '</button><span class="sr-only" id="games-life-playback-status" aria-live="polite"></span>' +
            '</div>';
        }
        html += '</div>';
        return html;
    }

    function _clearPlaybackTimer(sessionId) {
        if (_playbackTimers[sessionId]) global.clearTimeout(_playbackTimers[sessionId]);
        delete _playbackTimers[sessionId];
    }

    function _announcePlayback(root, message) {
        var status = root.querySelector('#games-life-playback-status');
        if (status) status.textContent = message;
    }

    function _paintFrame(root, sessionId, frame) {
        var boardElement = root.querySelector('.life-board');
        if (!boardElement || boardElement.getAttribute('data-life-session') !== String(sessionId)) {
            return false;
        }
        var cells = boardElement.querySelectorAll('.life-cell[data-cell-index]');
        for (var i = 0; i < cells.length; i++) {
            var cell = cells[i];
            var index = parseInt(cell.getAttribute('data-cell-index'), 10);
            var alive = _isAlive(frame.board, index);
            cell.classList.remove('alive');
            if (alive) cell.classList.add('alive');
            cell.setAttribute('aria-label', 'Row ' + (Math.floor(index / BOARD_SIDE) + 1) +
                ', column ' + ((index % BOARD_SIDE) + 1) + ': ' + (alive ? 'alive' : 'dead'));
        }
        boardElement.setAttribute('aria-label', 'Conway Life generation ' + frame.generation);
        boardElement.setAttribute('data-generation', String(frame.generation));
        var generationLabel = root.querySelector('.life-generation');
        var liveCountLabel = root.querySelector('.life-live-count');
        if (generationLabel) generationLabel.textContent = 'Generation ' + frame.generation;
        if (liveCountLabel) liveCountLabel.textContent = _liveCount(frame.board) + ' live';
        return true;
    }

    function _playFrames(session, context, loop) {
        var root = context && context.root ? context.root : global.document;
        var frames = _playbackFrames(session);
        if (!frames) return;

        _clearPlaybackTimer(session.game_id);
        delete _autoPlay[session.game_id];
        var index = 0;
        _announcePlayback(
            root,
            (loop ? 'Looping' : 'Playing') + ' generations ' + frames[0].generation +
                ' through ' + frames[frames.length - 1].generation
        );
        function showFrame() {
            _playbackFrame[session.game_id] = frames[index];
            if (!_paintFrame(root, session.game_id, frames[index])) {
                _looping[session.game_id] = false;
                delete _playbackTimers[session.game_id];
                delete _playbackFrame[session.game_id];
                return;
            }
            if (index < frames.length - 1) {
                index += 1;
                _playbackTimers[session.game_id] = global.setTimeout(showFrame, FRAME_HOLD_MS);
            } else if (loop && _looping[session.game_id]) {
                index = 0;
                _playbackTimers[session.game_id] = global.setTimeout(
                    showFrame,
                    FINAL_FRAME_HOLD_MS
                );
            } else {
                delete _playbackTimers[session.game_id];
                delete _playbackFrame[session.game_id];
                _announcePlayback(
                    root,
                    'Evolution complete at generation ' + frames[frames.length - 1].generation
                );
            }
        }
        showFrame();
    }

    function _bindBoard(session, context) {
        var root = context && context.root ? context.root : global.document;
        var replay = root.querySelector('#games-life-replay-btn');
        var showFinal = root.querySelector('#games-life-final-btn');
        var loop = root.querySelector('#games-life-loop-btn');
        var frames = _playbackFrames(session);
        var generation = parseInt(_meta(session, 'generation', 0), 10) || 0;
        var seenGeneration = _seenGenerations[session.game_id];
        if (seenGeneration !== undefined &&
                generation === seenGeneration + GENERATIONS_PER_HANDOFF && frames) {
            _autoPlay[session.game_id] = true;
        }
        _seenGenerations[session.game_id] = generation;
        if (_autoPlay[session.game_id]) {
            if (frames && !_prefersReducedMotion()) {
                _playFrames(session, context, false);
            } else {
                delete _autoPlay[session.game_id];
            }
        }
        if (replay) replay.addEventListener('click', function() {
            _looping[session.game_id] = false;
            if (loop) {
                loop.setAttribute('aria-pressed', 'false');
                loop.textContent = 'Loop';
            }
            _playFrames(session, context, false);
        });
        if (showFinal) showFinal.addEventListener('click', function() {
            _looping[session.game_id] = false;
            _clearPlaybackTimer(session.game_id);
            delete _autoPlay[session.game_id];
            delete _playbackFrame[session.game_id];
            if (loop) {
                loop.setAttribute('aria-pressed', 'false');
                loop.textContent = 'Loop';
            }
            if (frames) {
                _paintFrame(root, session.game_id, frames[frames.length - 1]);
                _announcePlayback(
                    root,
                    'Showing final generation ' + frames[frames.length - 1].generation
                );
            }
        });
        if (loop) loop.addEventListener('click', function() {
            var enabled = !_looping[session.game_id];
            _looping[session.game_id] = enabled;
            loop.setAttribute('aria-pressed', enabled ? 'true' : 'false');
            loop.textContent = enabled ? 'Stop loop' : 'Loop';
            if (enabled) {
                _playFrames(session, context, true);
            } else {
                _clearPlaybackTimer(session.game_id);
                delete _autoPlay[session.game_id];
                delete _playbackFrame[session.game_id];
                if (frames) _paintFrame(root, session.game_id, frames[frames.length - 1]);
            }
        });
    }

    function _activeStatusText(session, context) {
        if (_isLocalInitiator(session)) return 'Evolution verified · pass the Life Torch';
        var initiator = session.initiator || session.challenger || '';
        var name = context && context.contactName ? context.contactName(initiator) : 'Sender';
        return 'Waiting for ' + name + ' to pass the Life Torch';
    }

    function _detailChips(session) {
        if (_playbackFrames(session)) return ['24-generation evolution'];
        var board = _board(session);
        var generation = parseInt(_meta(session, 'generation', 0), 10) || 0;
        return ['Generation ' + generation, _liveCount(board) + ' live cells'];
    }

    function _statusClass(session) {
        return session.status === 'completed' ? 'status-complete' : '';
    }

    function _canRestart(session, sessions) {
        if (session.status !== 'completed') return true;
        if (_meta(session, 'holder', '') !== _localIdentity(session)) return false;

        var worldId = _meta(session, 'world_id', '');
        var generation = parseInt(_meta(session, 'generation', 0), 10);
        if (!Array.isArray(sessions) || !worldId || !Number.isSafeInteger(generation)) {
            return true;
        }
        return !sessions.some(function(candidate) {
            if (!candidate || candidate.game_id === session.game_id ||
                    candidate.app_id !== APP_ID ||
                    ['pending', 'active', 'completed'].indexOf(candidate.status) === -1 ||
                    _meta(candidate, 'world_id', '') !== worldId) {
                return false;
            }
            var candidateGeneration = parseInt(_meta(candidate, 'generation', -1), 10);
            return Number.isSafeInteger(candidateGeneration) && candidateGeneration >= generation;
        });
    }

    function _restartLabel(session) {
        return session.status === 'completed' ? 'Continue evolution' : 'New invitation';
    }

    function _restartPayload(session, sessions) {
        if (!_canRestart(session, sessions)) return null;
        if (session.status !== 'completed') return {};
        var board = _meta(session, 'board', '');
        var worldId = _meta(session, 'world_id', '');
        var generation = parseInt(_meta(session, 'generation', 0), 10);
        if (!_decodeBoard(board) || !/^[0-9a-f]{16}$/.test(worldId) || !Number.isSafeInteger(generation)) {
            return null;
        }
        return { b: board, g: generation, w: worldId };
    }

    function _renderActiveControls(session) {
        if (_isLocalInitiator(session)) {
            return '<button class="nr-btn games-ctrl-accept" id="games-life-award-btn">' +
                'Pass the Life Torch</button>';
        }
        return '<span class="games-ctrl-waiting">Waiting for the sender to pass the Life Torch...</span>';
    }

    function _bindControls(session, controls) {
        if (!_isLocalInitiator(session) || !controls) return;
        controls.bindButton('games-life-award-btn', function() {
            controls.sendAction('move', {});
        });
    }

    if (!RS.games.views.has(APP_ID)) {
        RS.games.views.register(APP_ID, {
            displayName: "Conway's Game of Life",
            icon: '\uD83D\uDC7E',
            participantLabel: 'with',
            participantPickerLabel: 'Contact',
            challengeLabel: 'invitation',
            challengeVerb: 'invite',
            themeClass: 'games-theme-life',
            boardSelector: '.life-board',
            actions: ['challenge', 'accept', 'move', 'decline', 'error'],
            renderBoard: _renderBoard,
            bindBoard: _bindBoard,
            activeStatusText: _activeStatusText,
            statusClass: _statusClass,
            detailChips: _detailChips,
            onSessionDelta: _onSessionDelta,
            restartLabel: _restartLabel,
            canRestart: _canRestart,
            restartPayload: _restartPayload,
            renderActiveControls: _renderActiveControls,
            bindControls: _bindControls,
        });
    }
})(window);
