// Extracted unchanged from dashboard/static/js/identity.js at eb5f2df; see SOURCE.md.
// Blockies-style SVG identicon. Adapted from https://github.com/download13/blockies (MIT).
var blockies = (function() {
    function seedRand(seed) {
        var s = [0, 0, 0, 0];
        for (var i = 0; i < seed.length; i++) {
            s[i % 4] = (s[i % 4] << 5) - s[i % 4] + seed.charCodeAt(i);
        }
        return function() {
            var t = s[0] ^ (s[0] << 11);
            s[0] = s[1]; s[1] = s[2]; s[2] = s[3];
            s[3] = (s[3] ^ (s[3] >> 19) ^ t ^ (t >> 8)) >>> 0;
            return s[3] / ((1 << 31) >>> 0);
        };
    }

    function createColor(rand) {
        var h = Math.floor(rand() * 360);
        var s = ((rand() * 60) + 40);
        var l = ((rand() + rand() + rand() + rand()) * 25);
        return 'hsl(' + h + ',' + s + '%,' + l + '%)';
    }

    function createImageData(rand, gridSize) {
        var w = gridSize, h = gridSize;
        var halfW = Math.ceil(w / 2);
        var data = [];
        for (var y = 0; y < h; y++) {
            var row = [];
            for (var x = 0; x < halfW; x++) {
                // 0 = bg, 1 = primary, 2 = spot
                row.push(Math.floor(rand() * 2.3));
            }
            var fullRow = row.slice();
            for (var x = Math.floor(w / 2) - 1; x >= 0; x--) {
                fullRow.push(row[x]);
            }
            data.push(fullRow);
        }
        return data;
    }

    var fn = function(seed, svgSize) {
        var gridSize = 8;
        var rand = seedRand(seed || '');
        var color = createColor(rand);
        var bgcolor = createColor(rand);
        var spotcolor = createColor(rand);
        var grid = createImageData(rand, gridSize);

        var rects = '';
        for (var y = 0; y < gridSize; y++) {
            for (var x = 0; x < gridSize; x++) {
                var val = grid[y][x];
                var fill = val === 0 ? bgcolor : val === 1 ? color : spotcolor;
                rects += '<rect x="' + x + '" y="' + y + '" width="1" height="1" fill="' + fill + '"/>';
            }
        }

        return '<svg xmlns="http://www.w3.org/2000/svg" width="' + svgSize +
            '" height="' + svgSize + '" viewBox="0 0 ' + gridSize + ' ' + gridSize +
            '" shape-rendering="crispEdges" style="display:block;border-radius:50%;clip-path:circle(50% at 50% 50%);overflow:hidden;">' +
            rects + '</svg>';
    };
    return fn;
})();

// Cache avatars per (hash, size) — blockies PRNG + 64 SVG rects is expensive per call.
var _avatarCache = {};
function identityAvatar(hashValue, size) {
    if (!hashValue) {
        var color = 'var(--text-muted)';
        var radius = size / 2;
        return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size +
            '" style="display:block;border-radius:50%;clip-path:circle(50% at 50% 50%);overflow:hidden;">' +
            '<circle cx="' + radius + '" cy="' + radius + '" r="' + radius + '" fill="' + color + '" opacity="0.3"/>' +
            '</svg>';
    }
    var key = hashValue + '|' + size;
    if (_avatarCache[key]) return _avatarCache[key];
    var svg = blockies(hashValue, size);
    _avatarCache[key] = svg;
    return svg;
}


export { identityAvatar };
