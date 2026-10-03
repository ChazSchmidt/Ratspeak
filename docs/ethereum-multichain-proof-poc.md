# RatSpeak five-network Ethereum proof of concept

Branch: `ethereum-multichain-proof-poc`

## Goal

Prove that RatSpeak can use one user experience and one shared EVM proof layer
across five test networks:

| Network | Chain ID | Verifier family |
| --- | ---: | --- |
| Ethereum Sepolia | 11155111 | Ethereum Beacon / Helios |
| Base Sepolia | 84532 | OP Stack |
| OP Sepolia | 11155420 | OP Stack |
| Arbitrum Sepolia | 421614 | Nitro |
| Robinhood Chain Testnet | 46630 | Nitro |

The user should not configure RPC endpoints, consensus clients, SystemConfig
contracts, Rollup contracts, storage slots, or proof roots.

## Shared architecture

Every stack-specific verifier terminates in `VerifiedEvmAnchor`:

```
VerifiedEvmAnchor
  chain_id
  block_number
  block_hash
  parent_hash
  state_root
  transactions_root
  receipts_root
  timestamp
  assurance
  evidence_hash
```

Everything below that boundary is shared:

- EIP-1186 account proof verification
- contract storage proof verification
- ERC-20 balance proof interpretation
- transaction trie proof verification
- receipt trie proof verification
- EIP-1559 signing
- native ETH clear signing
- ERC-20 `transfer(address,uint256)` clear signing
- exact signed-byte relay over the existing RatSpeak gateway/LXMF path

RPC responses remain untrusted byte sources.

## Ethereum Sepolia

The existing RatSpeak Helios flow remains the parent-chain trust root. A
consensus-authenticated Ethereum execution block can be converted to the shared
anchor with `AnchorAssurance::EthereumFinalized`.

Ethereum Sepolia also supplies the L1 state and receipt proofs used to
authenticate the two L2 verifier families.

## OP Stack

`OpStackSequencerAnchor` is shared by Base Sepolia and OP Sepolia.

The flow is:

1. use the Ethereum Sepolia light-client anchor;
2. request the chain's SystemConfig account + unsafe-signer storage proof;
3. verify those proofs locally;
4. verify the sequencer signature over the exact decompressed OP commitment;
5. decode the SSZ execution payload;
6. require an RPC-supplied L2 RLP header to hash to that payload and match its
   state/receipt roots;
7. emit a shared `VerifiedEvmAnchor`.

The current assurance is deliberately named
`AnchorAssurance::SequencerAuthenticated`. It is not presented as L1-derived
safe/finalized state.

The online agent may decompress the OP feed payload before transporting it.
Decompression is not trusted because RatSpeak verifies the signature over the
exact decompressed bytes.

### Current OP limitation

The verifier is generic for Base Sepolia and OP Sepolia, but the PoC still
needs a production-quality agent source for the Helios-compatible signed
commitment on each OP Stack chain. The chain registry contains the SystemConfig
and RPC hints; the phone does not trust those endpoints.

## Nitro

`NitroConfirmedEndpoint` is shared by Arbitrum Sepolia and Robinhood Chain
Testnet.

The strong PoC path is:

1. use a finalized Ethereum Sepolia anchor;
2. verify the exact L1 transaction + receipt proof locally;
3. require an `AssertionConfirmed(bytes32,bytes32,bytes32)` log from the
   configured Nitro Rollup contract;
4. extract the confirmed Nitro L2 block hash;
5. require the endpoint L2 RLP header to hash to that value;
6. optionally walk contiguous parent headers to an earlier target;
7. emit `VerifiedEvmAnchor` with
   `AnchorAssurance::RollupConfirmed`.

This avoids embedding Nitro execution or a fraud-proof VM in RatSpeak.

### Future Nitro compression

The current historical path uses contiguous parent headers. BoLD already
commits to histories with Keccak Merkle roots and inclusion proofs. A later
optimization can replace long header ancestry with BoLD history inclusion
proofs without changing the shared EVM anchor API.

## Chain definitions

`chains.rs` contains the five built-in PoC definitions and the minimum
stack-specific configuration:

- parent chain
- verifier family
- SystemConfig for OP Stack
- Rollup contract for Nitro
- native ETH metadata
- optional RPC/feed hints for the online agent

These are application support data, not user settings.

## Asset installation

The user-facing concept is one asset.

Internally an ERC-20 asset keeps two independent definitions:

1. clear-sign definition: what an operation means;
2. balance-proof definition: how to derive and interpret the token's storage.

`DefinitionRegistry::install_asset_bundle` validates that both definitions
refer to the same chain, contract, symbol and decimals, then installs them
atomically.

The app can therefore present:

```
Add USDC on Base
```

rather than asking the user to install two definitions or configure Base.

Native ETH support for all five PoC networks is installed with
`install_poc_native_definitions()`.

## Verified balances

`EvmAnchorRpcProvider::fetch_verified_storage_evidence` performs one anchored
`eth_getProof(contract,[storageKey])` request and produces:

- a locally verified contract account proof;
- a locally verified storage-slot proof.

A balance definition derives the storage key and interprets the resulting
value. Base Sepolia USDC is the real-world fixture already included in the
branch.

## Transaction preparation and signing

The online agent may suggest nonce, gas limit, max fee and priority fee.

RatSpeak locally derives human-readable meaning from an installed definition,
constructs the exact EIP-1559 transaction, binds the chain ID and all mutable
fields into the review, and signs only those exact canonical bytes after user
authorization.

The same clear-sign wallet path is exercised in source tests for native ETH and
an ERC-20 transfer on all five chain IDs.

## Relay

The gateway/LXMF signed-relay boundary now accepts supported-chain EIP-1559
calls rather than only 21,000-gas Sepolia native transfers.

The decoded chain ID is retained on `AcceptedSignedRelay`, allowing the app or
agent service to route the transaction to the correct chain-specific provider
without asking the user to select an RPC.

The transport protocol itself was not expanded into an RPC configuration
protocol.

## Shared RPC proof collection

`CompleteBlockReceiptProofBackend::new_for_chain` reconstructs transaction
and receipt tries from ordinary EVM JSON-RPC for any supported chain.

`EvmAnchorRpcProvider` is bound to one verified chain anchor and can:

- submit a signed relay for that chain;
- fetch and locally verify account proofs;
- fetch and locally verify account + storage proofs for balances;
- fetch and locally verify exact transaction/receipt evidence.

The legacy Sepolia provider remains intact for compatibility.

## RTEST fixture

`experiments/ethereum-multichain/RatSpeakTestToken.sol` is one minimal ERC-20
for all five testnets.

Its `balanceOf` mapping is deliberately storage slot 0. The deployment
manifest is:

`experiments/ethereum-multichain/rtest-deployments.json`

Live addresses remain null until the contract is actually deployed. No
addresses are fabricated in this branch.

Once deployed, each chain gets the same RTEST definition semantics with only
chain ID and contract address changing.

## User experience

The target surface is demonstrated in
`dashboard/ethereum-multichain-proof-poc.html`.

The normal user sees:

- assets;
- network names;
- verified balances;
- Send;
- Add asset;
- `Ready for offline use ✓`.

Technical proof details are behind disclosure UI.

The intended dependency behavior is automatic:

```
install asset
  -> ensure its built-in chain support exists
  -> ensure Ethereum Sepolia bootstrap is fresh when required
  -> install clear-sign + balance definitions
  -> report Ready for offline use
```

Fresh L2 headers and proof nodes do not need to be preinstalled. They can arrive
later over RatSpeak and are accepted only after local verification.

## Assurance labels

The verifier distinguishes:

- `EthereumFinalized`
- `SequencerAuthenticated`
- `RollupConfirmed`

The normal UI may simply say `Verified`, but technical details must preserve
the actual assurance rather than making a sequencer head look finalized.

## Verification status in this environment

No new GitHub Actions workflow was added.

The earlier experiment-specific workflow was removed. This chat environment
does not have the repository mounted locally and cannot clone it through normal
outbound DNS, so the new Rust changes have not been compiled in this execution
environment. A bounded source-level consistency pass and lockfile dependency
update were performed.

Before treating the branch as executable evidence, run locally:

```
cargo fmt --all -- --check
cargo check -p ratspeak-eth-verifier --locked
cargo test -p ratspeak-eth-verifier --locked
cargo test -p ratspeak-eth-clearsign --locked
cargo test -p ratspeak-eth-wallet --locked
cargo test -p ratspeak-eth-gateway --locked
```

Do not add a dedicated CI workflow solely for this experiment.

## Remaining work

1. Compile and fix any API/version mismatches discovered by Cargo.
2. Exercise a real Base Sepolia signed OP commitment end-to-end.
3. Establish the equivalent signed-commitment source for OP Sepolia.
4. Exercise a real Arbitrum Sepolia `AssertionConfirmed` L1 receipt proof.
5. Exercise the same Nitro path against Robinhood Chain Testnet.
6. Deploy RTEST to the five networks and fill the deployment manifest.
7. Generate/install RTEST clear-sign + balance definitions from those addresses.
8. Wire the static demo concepts into the Android UI.
9. Later: replace long Nitro parent-header ancestry with BoLD history inclusion
   proofs.
