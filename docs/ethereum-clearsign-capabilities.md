# Ethereum clear-sign capabilities experiment

Branch: `ethereum-clearsign-capabilities`  
Base: `a9547aef922cbad874d9ad81806e46a5a7d5e0fb`

## Purpose

Prove the "RatSpeak understands" boundary without building the remote agent,
smart account, paymaster, or production wallet architecture.

The rule is strict: **no matching installed trusted definition = no signature**.

## Existing signing path preserved

The existing `ratspeak-eth-wallet` PoC prepares an EIP-1559 transaction,
stores its canonical signing bytes, computes the transaction signing hash, binds
those values into a review digest, requires an immediate native authorizer, then
signs and re-decodes the signed envelope to verify fields and recovered sender.

This experiment adds a parallel `PreparedClearSignedOperation` path instead of
rewriting that Sepolia native-transfer path.

## Narrow insertion point

`ratspeak-eth-clearsign` sits immediately before transaction preparation:

`untrusted operation -> installed definition registry -> decoded review -> immutable prepared EIP-1559 transaction -> native authorizer -> signature`

The remote party supplies transaction facts, not trusted meaning.

## ERC-7730 compatibility

The contract fixtures use the ERC-7730 v2 structure that matters to this
prototype:

- `context.contract.deployments[]` for exact chain/address binding
- `display.formats` keyed by a human-readable ABI fragment
- selector derivation by stripping parameter names and hashing the canonical
  type-only function signature
- `intent` and field format checks for recipient and token amount

The parser intentionally supports only
`transfer(address to,uint256 value)` in this branch. It derives and checks
selector `0xa9059cbb` and rejects every other function, including
`approve(address,uint256)`.

Token name, ticker, and decimals use ERC-7730 v2’s standard `metadata.token`
object. RatSpeak derives a local definition ID from chain ID + contract address +
selector, while the SHA-256-like role of exact version identity is filled by the
Keccak-256 hash of the installed descriptor bytes. The user-installed descriptor
is the offline trust source in this experiment; production still needs signed
publisher/update policy.

Native ETH has no contract context or calldata, so it uses a small RatSpeak
native-transfer definition. It shares the same registry and review output but
is not claimed to be ERC-7730.

## Included definitions

- Base native ETH: 18 decimals
- Base USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, 6 decimals
- Base alUSDb: `0x877014E21c32feA108B6A1f45f367efc9a2d9B9F`, 18 decimals
- Base RATSPEAK: `0xf1e9Baa65d418A9025e1851DD2D37f1AD208bba3`, 18 decimals

The alUSDb address/name/symbol are cross-checked against Alchemix's current V3
Base deployment source. USDC is the current Circle Base deployment. RATSPEAK's
address is the project-supplied deployment and 18-decimal metadata is
cross-checked against current Base token lists. Before production use, contract
code identity / proxy implementation state should be pinned as well.

## Exact authorization binding

For clear-signed operations, RatSpeak constructs `TxEip1559` first and calls
`encoded_for_signing()`. The device-held key signs:

`keccak256(canonical EIP-1559 signing bytes)`

The review digest additionally commits to:

- operation id
- installed definition hash
- decoded operation hash
- sender
- nonce
- gas limit
- max fee per gas
- max priority fee per gas
- review lifetime
- canonical signing bytes
- EIP-1559 signing hash

Immediately before authorization/signing, the transaction is re-encoded and all
bindings are recomputed. Any mutation causes
`ClearSignedOperationChanged` before the authorizer is called.

## Fail-closed tests

`ratspeak-eth-clearsign` tests cover:

- native Base ETH transfer
- Base USDC transfer
- Base alUSDb transfer
- Base RATSPEAK transfer
- same generic ERC-20 decoder for all three tokens
- unknown ERC-20 contract
- wrong chain
- unsupported `approve()`
- modified recipient changes the bound operation hash
- modified amount changes the bound operation hash
- removing USDC definition makes USDC unsignable

`ratspeak-eth-wallet` tests additionally cover:

- clear-signed ERC-20 review -> exact EIP-1559 signing bytes -> signature
- calldata mutation after review is rejected before native authorization
- unknown contract / `approve()` never reach the authorizer

## Installation model

The registry can load a directory of JSON definitions and has atomic-ish
file-based `install_file` / `remove_file` helpers for the experiment.
Definition identity replacement is explicit: installing the same derived local
ID replaces the in-memory version. Native definitions carry their own constrained
RatSpeak-local ID.

This is not yet a trust-distribution system. Production work still needs a
signature/trust model for descriptor packages, rollback/version policy, and
safe update UX.

## Proxy and stale-definition policy

This branch pins chain + contract address and fails closed for anything else. It
does **not** yet prove deployed bytecode or proxy implementation identity. For
upgradeable contracts, a stale definition could remain syntactically
applicable after semantics change. Before connecting this experiment to an
agent or real funds, add code-hash / implementation pinning or another
verifiable freshness mechanism.

## Explicitly out of scope

- remote agent protocol
- smart-account permissions
- paymasters/bundlers
- WalletConnect
- portfolio/token discovery
- swaps or arbitrary ABI interpretation
- arbitrary ERC-7730 format support
- production descriptor trust/update service
