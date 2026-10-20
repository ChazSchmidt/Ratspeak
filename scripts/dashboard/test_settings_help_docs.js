'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var vm = require('vm');

var dashboardRoot = path.join(__dirname, '..', '..', 'dashboard');
var indexSource = fs.readFileSync(path.join(dashboardRoot, 'index.html'), 'utf8');
var settingsSource = fs.readFileSync(path.join(dashboardRoot, 'static', 'js', 'settings.js'), 'utf8');

// The entry lives in the Settings section list so it shows in the desktop
// sidebar and in the mobile section index, but it is not a panel.
var navStart = indexSource.indexOf('id="settings-section-nav"');
var navEnd = indexSource.indexOf('</nav>', navStart);
assert(navStart >= 0 && navEnd > navStart, 'missing settings section nav');
var nav = indexSource.slice(navStart, navEnd);
var entryStart = nav.indexOf('id="settings-help-docs"');
assert(entryStart >= 0, 'Help Docs entry must be in the settings section nav');
var entry = nav.slice(nav.lastIndexOf('<button', entryStart), nav.indexOf('</button>', entryStart));
assert(entry.includes('<span class="settings-nav-label">Help Docs</span>'));
assert(entry.includes('docs.ratspeak.org'));
assert(!entry.includes('data-settings-panel'), 'Help Docs must not be treated as a settings panel');
assert(nav.indexOf('data-settings-panel="panel-settings-system"') < entryStart,
    'Help Docs should follow the System section');

assert(settingsSource.includes("var SETTINGS_HELP_DOCS_URL = 'https://docs.ratspeak.org/';"));
assert(settingsSource.includes("helpDocs.addEventListener('click', openSettingsHelpDocs);"));

var start = settingsSource.indexOf('function openSettingsHelpDocs()');
var end = settingsSource.indexOf('\nfunction initSettingsSectionNav', start);
assert(start >= 0 && end > start, 'missing openSettingsHelpDocs source');

function load(openExternalUrl) {
    var toasts = [];
    var opened = [];
    var context = {
        window: {},
        showToast: function(message, kind) { toasts.push({ message: message, kind: kind }); },
        SETTINGS_HELP_DOCS_URL: 'https://docs.ratspeak.org/'
    };
    if (openExternalUrl) {
        context.RS = {
            openExternalUrl: function(url) {
                opened.push(url);
                return openExternalUrl(url);
            }
        };
        context.window.RS = context.RS;
    }
    vm.createContext(context);
    vm.runInContext(settingsSource.slice(start, end), context);
    return { open: context.openSettingsHelpDocs, toasts: toasts, opened: opened };
}

(async function() {
    var ok = load(function() { return Promise.resolve(true); });
    assert.strictEqual(await ok.open(), true);
    assert.deepStrictEqual(ok.opened, ['https://docs.ratspeak.org/']);
    assert.strictEqual(ok.toasts.length, 0);

    var refused = load(function() { return Promise.resolve(false); });
    assert.strictEqual(await refused.open(), false);
    assert.strictEqual(refused.toasts.length, 1);
    assert.strictEqual(refused.toasts[0].kind, 'toast-error');

    var thrown = load(function() { return Promise.reject(new Error('no browser')); });
    assert.strictEqual(await thrown.open(), false);
    assert.strictEqual(thrown.toasts.length, 1);

    var missing = load(null);
    assert.strictEqual(await missing.open(), false);
    assert.strictEqual(missing.toasts.length, 1);

    console.log('settings help docs: ok');
})().catch(function(error) {
    console.error(error);
    process.exit(1);
});
