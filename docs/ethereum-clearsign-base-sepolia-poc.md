# Base Sepolia clear-sign proof of concept

Branch: `ethereum-clearsign-base-sepolia-poc`

This branch forks the installable clear-sign experiment and targets Base Sepolia
(chain ID 84532) so the complete flow can be exercised without real Base assets.

## Working scope

The clear-sign interpreter now recognizes Base Sepolia and includes two
installable definitions:

- native ETH on Base Sepolia
- Circle USDC on Base Sepolia at
  `0x036CbD53842c5426634e7929541eC2318f3dCF7e`

The USDC definition uses the same ERC-7730 v2
`transfer(address,uint256)` path as the Base-mainnet fixtures. No
Base-Sepolia-specific ERC-20 decoder exists.

The wallet clear-sign path is already chain-generic. Once the installed
definition approves the operation, the exact EIP-1559 transaction is encoded
and signed with chain ID 84532.

## Proof architecture

The existing Ethereum Sepolia verifier cannot simply be relabeled Base Sepolia.
It currently establishes authority with Ethereum Sepolia Beacon consensus and
then verifies account / receipt tries under that execution header.

For Base Sepolia the intended replacement is:

`Helios OP Stack Base-Sepolia verification -> verified L2 execution header/root -> existing trie-proof machinery`

The Helios revision already pinned by RatSpeak
(`204c998a927348e1c000a664f08d5b37b1b0d924`) contains
`helios-opstack` and an explicit `Network::BaseSepolia` configuration with
chain ID 84532 and Ethereum Sepolia as its L1 network.

The next implementation step is intentionally narrow: expose a Base-Sepolia
verified execution anchor from the Helios OP-Stack client, then make RatSpeak's
account/receipt proof verifier consume that anchor instead of an Ethereum
Sepolia Beacon-derived execution header.

No rsLXMF transport change is expected.
