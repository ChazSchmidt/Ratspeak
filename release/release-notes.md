## v1.0.34

### Added

- Added voice messages for compatible handhelds, with the recording format selected automatically.
- Added Codec2 support for compatible low-bandwidth voice calls.

### Fixed and improved

- Improved Windows Bluetooth discovery and reconnection, including saved devices missing from scan results.
- Fixed Android Bluetooth cleanup when permissions are revoked.
- Kept recorded clips available for retry and prevented duplicate voice messages after an uncertain send result.
- Improved recording limits, voice controls, and handling when leaving a chat or changing identities.
- Removed legacy text fallbacks for message reactions.

### Build and compatibility

- Source builds require Rust 1.89 or later.
- Compact recordings are limited to 15 seconds. Receive the handheld's announce before recording so the app can select its compatible format.

### Known issue

- Some attachments sent to NomadNet may appear delivered without being saved by the receiver due to an upstream Python Reticulum issue.
