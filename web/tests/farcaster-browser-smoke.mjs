import assert from 'node:assert/strict';

// Negative UI boundary test only: never begin a consented relay request.
export async function testFarcasterSmoke(browser, url) {
  const navigate = async (page, view) => {
    if (await page.locator('#bottom-bar-hamburger').isVisible()) {
      await page.locator('#bottom-bar-hamburger').click();
      await page.locator(`#bottom-sheet [data-view="${view}"]`).click();
    } else await page.locator(`#sidebar [data-view="${view}"]`).click();
  };
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const externalRequests = [], pageErrors = [];
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin !== new URL(url).origin) {
      externalRequests.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  try {
    const page = await context.newPage();
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.goto(url);
    assert.equal(await page.locator('#farcaster-start').count(), 0, 'Optional UI must stay lazy before opening');
    await navigate(page, 'identity');
    await page.locator('#passphrase').fill('disposable farcaster smoke password');
    await page.locator('#create').click();
    await page.waitForFunction(() => /^[0-9a-f]{32}$/.test(document.querySelector('#address').textContent));
    const address = await page.locator('#address').textContent();
    const open = async () => {
      await navigate(page, 'settings');
      if (await page.locator('#settings-mobile-back-btn').isVisible()) await page.locator('#settings-mobile-back-btn').click();
      await page.locator('[data-settings-panel="panel-settings-browser"]').click();
      await page.locator('#open-farcaster').click();
      await page.locator('#farcaster-start').waitFor();
    };
    const assertCleared = async () => {
      assert.equal(await page.locator('#farcaster-consent').isChecked(), false, 'Reset must clear consent for another optional session/identity');
      assert.equal(await page.locator('#farcaster-auth-link').isHidden(), true);
      assert.equal(await page.locator('#farcaster-auth-link').getAttribute('href'), null);
      assert.equal(await page.locator('#farcaster-check').isHidden(), true);
      assert.equal(await page.locator('#farcaster-start').isEnabled(), true);
    };
    await open();
    await assertCleared();
    await page.locator('#farcaster-start').click();
    await page.getByText('Consent is required to link your public FID and LXMF address through Farcaster authentication.', { exact: true }).waitFor();
    assert.deepEqual(externalRequests, [], 'Start without consent must make no relay/RPC request');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'No mobile horizontal overflow');
    assert.equal(await page.locator('#farcaster-dialog').evaluate(dialog => dialog.scrollWidth <= dialog.clientWidth), true, 'No dialog horizontal overflow');
    // Check consent only, without starting authentication or sending any request.
    await page.locator('#farcaster-consent').check();
    await page.locator('#close-farcaster').click();
    await open();
    await assertCleared();
    // Calling the real Lock button handler while the modal is open also resets it.
    await page.locator('#farcaster-consent').check();
    await page.evaluate(() => document.querySelector('#lock').click());
    await page.waitForFunction(() => document.querySelector('#address').textContent === '');
    await assertCleared();
    await page.locator('#close-farcaster').click();
    await navigate(page, 'identity');
    await page.locator('#passphrase').fill('disposable farcaster smoke password');
    await page.locator('#unlock').click();
    await page.waitForFunction(expected => document.querySelector('#address').textContent === expected, address);
    await open();
    await assertCleared();
    assert.deepEqual(externalRequests, [], 'Negative smoke test must never contact external services');
    assert.deepEqual(pageErrors, [], 'No uncaught optional UI errors');
    console.log(JSON.stringify({ pass: true, optionalFarcasterLoaded: true, consentRequired: true, noConsentExternalRequests: externalRequests.length, closeReopenReset: true, identityLockReset: true, mobileOverflow: false, uncaughtOptionalPageErrors: pageErrors.length, liveFarcasterApproval: false }));
  } finally { await context.close(); }
}
