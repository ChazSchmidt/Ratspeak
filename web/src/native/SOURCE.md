# Native Ratspeak UI source

Reference: ChazSchmidt/Ratspeak commit eb5f2df7e86696bf6b61691b598601cb20572d0b.
https://github.com/ChazSchmidt/Ratspeak/tree/eb5f2df7e86696bf6b61691b598601cb20572d0b/dashboard

The css/ and fonts/ files are copied byte-for-byte from dashboard/static/.
identity-avatar.js is the native identity.js lines 451–533 helper and its blockies dependency, with an ES module export. Its existing MIT attribution is retained.
The browser index reuses native dashboard/index.html header, rat SVG, navigation buttons, profile strip, search, chat header, compose/send controls, mobile FAB and bottom bar. Dynamic rows adapt native lxmf.js conversation, contact and message DOM to the existing browser MessagingClient. Contacts reuse the standalone search/grouped-list view and native contact-detail sheet with public-address copy and Message actions. Settings reuse the native section/detail shell and mobile back navigation for Network and browser-only privacy/discovery settings.

Browser-only differences: Identity uses the existing encrypted local vault; Settings configures a WebSocket gateway; native-only destinations/actions are omitted rather than simulated. Farcaster remains an optional Settings dialog. Native delivery/read indicators are not reused for mere link writes. A separate short-text Ratspeak Android exchange received a signature-verified reply; the phone version and broader interoperability remain unknown. No full native feature parity is claimed.

Remaining native features are deliberately absent, not recreated: contact edit/block/remove, live presence, rich message actions, attachments, voice and delivery-type controls. Browser message history and drafts are tab-local and cleared on lock. Desktop/mobile native comparison and the full isolated browser regression passed on 2026-10-20; see [the validation record](../../tests/BROWSER-VALIDATION.md) for measured matches, remaining differences, and limits. A successful build alone does not establish visual fidelity or network interoperability.

Source path | Git blob SHA
--- | ---
+dashboard/static/css/00-palettes.css | 24bba6449c983a30ed3c42df638b0963b246c133
dashboard/static/css/00-tokens.css | 4b8ea80ba438fde2195f6ac67c4eb9b9c589ebde
dashboard/static/css/01-reset.css | faf2bebde5c676997f99dae726643bf91ac8d64e
dashboard/static/css/02-typography.css | 929c7bbdd7543374ce8ed3fa9a5b3999da601e9d
dashboard/static/css/03-scrollbar.css | 4fe6fb56239125f86a76e0a5229c7386d40dee6b
dashboard/static/css/04-layout.css | 22840e265ec472e45df13beeb806afc6b846abca
dashboard/static/css/05-panels.css | 250b8013e95db013fd59a9529deeb548c0f7f20f
dashboard/static/css/06-forms.css | 69d0a8156914639f07f5d657398bdd4b605d3e65
dashboard/static/css/07-components.css | 1c894a405bcbc400abfa2b9b547eec6015186ea2
dashboard/static/css/08-modals.css | c181227f382a9f6bfb18b660e49352c55dc54c26
dashboard/static/css/09-messaging.css | c76f74725515d705e68705674982bb3816f1e24e
dashboard/static/css/13-responsive.css | e3bbecc1328852be220099279f8075de64bde2f8
dashboard/static/fonts/fonts.css | d43ecf260c511750d00d852b61cb3462dab67513
dashboard/static/css/10-views.css | 21b1a0e17877559b78a5f0e93b54c7252b272103
fonts/Outfit-latin.woff2 | 48aae950fc21da407d5577e7ce63e028bf9bb205
fonts/JetBrainsMono-latin.woff2 | 2ca6ac605954ee884442db8ea1d61093000bcc29
fonts/Outfit-latin-ext.woff2 | 8fa75fd9ee81a8da01698d1d3400670bb8d508d7
fonts/JetBrainsMono-latin-ext.woff2 | 310faddfdd181f2dbef10b26ce9231504762d045
