use alloy_primitives::{Address, address};

pub const ETHEREUM_SEPOLIA_CHAIN_ID: u64 = 11_155_111;
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;
pub const OP_SEPOLIA_CHAIN_ID: u64 = 11_155_420;
pub const ARBITRUM_SEPOLIA_CHAIN_ID: u64 = 421_614;
pub const ROBINHOOD_TESTNET_CHAIN_ID: u64 = 46_630;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationFamily {
    EthereumBeacon,
    OpStack,
    Nitro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpStackConfig {
    pub system_config: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NitroConfig {
    pub rollup: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackConfig {
    Ethereum,
    OpStack(OpStackConfig),
    Nitro(NitroConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainDefinition {
    pub chain_id: u64,
    pub network: &'static str,
    pub display_name: &'static str,
    pub family: VerificationFamily,
    pub parent_chain_id: Option<u64>,
    pub native_symbol: &'static str,
    pub native_decimals: u8,
    pub stack: StackConfig,
    /// PoC-only endpoint hint used by an online agent. The phone never treats
    /// the endpoint as authoritative and never needs the user to configure it.
    pub rpc_hint: Option<&'static str>,
    pub sequencer_feed_hint: Option<&'static str>,
}

pub const ETHEREUM_SEPOLIA: ChainDefinition = ChainDefinition {
    chain_id: ETHEREUM_SEPOLIA_CHAIN_ID,
    network: "sepolia",
    display_name: "Ethereum Sepolia",
    family: VerificationFamily::EthereumBeacon,
    parent_chain_id: None,
    native_symbol: "ETH",
    native_decimals: 18,
    stack: StackConfig::Ethereum,
    rpc_hint: None,
    sequencer_feed_hint: None,
};

pub const BASE_SEPOLIA: ChainDefinition = ChainDefinition {
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    network: "base-sepolia",
    display_name: "Base Sepolia",
    family: VerificationFamily::OpStack,
    parent_chain_id: Some(ETHEREUM_SEPOLIA_CHAIN_ID),
    native_symbol: "ETH",
    native_decimals: 18,
    stack: StackConfig::OpStack(OpStackConfig {
        system_config: address!("f272670eb55e895584501d564AfEB048bEd26194"),
    }),
    rpc_hint: Some("https://sepolia.base.org"),
    sequencer_feed_hint: None,
};

pub const OP_SEPOLIA: ChainDefinition = ChainDefinition {
    chain_id: OP_SEPOLIA_CHAIN_ID,
    network: "op-sepolia",
    display_name: "OP Sepolia",
    family: VerificationFamily::OpStack,
    parent_chain_id: Some(ETHEREUM_SEPOLIA_CHAIN_ID),
    native_symbol: "ETH",
    native_decimals: 18,
    stack: StackConfig::OpStack(OpStackConfig {
        system_config: address!("034edD2A225f7f429A63E0f1D2084B9E0A93b538"),
    }),
    rpc_hint: Some("https://sepolia.optimism.io"),
    sequencer_feed_hint: None,
};

pub const ARBITRUM_SEPOLIA: ChainDefinition = ChainDefinition {
    chain_id: ARBITRUM_SEPOLIA_CHAIN_ID,
    network: "arbitrum-sepolia",
    display_name: "Arbitrum Sepolia",
    family: VerificationFamily::Nitro,
    parent_chain_id: Some(ETHEREUM_SEPOLIA_CHAIN_ID),
    native_symbol: "ETH",
    native_decimals: 18,
    stack: StackConfig::Nitro(NitroConfig {
        rollup: address!("042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4"),
    }),
    rpc_hint: Some("https://sepolia-rollup.arbitrum.io/rpc"),
    sequencer_feed_hint: Some("wss://sepolia-rollup.arbitrum.io/feed"),
};

pub const ROBINHOOD_TESTNET: ChainDefinition = ChainDefinition {
    chain_id: ROBINHOOD_TESTNET_CHAIN_ID,
    network: "robinhood-testnet",
    display_name: "Robinhood Chain Testnet",
    family: VerificationFamily::Nitro,
    parent_chain_id: Some(ETHEREUM_SEPOLIA_CHAIN_ID),
    native_symbol: "ETH",
    native_decimals: 18,
    stack: StackConfig::Nitro(NitroConfig {
        rollup: address!("dc5F8E399DBd8a9F5F87AeC4C23Beb12431b386D"),
    }),
    rpc_hint: Some("https://rpc.testnet.chain.robinhood.com"),
    sequencer_feed_hint: Some("wss://feed.testnet.chain.robinhood.com"),
};

pub static SUPPORTED_CHAINS: [ChainDefinition; 5] = [
    ETHEREUM_SEPOLIA,
    BASE_SEPOLIA,
    OP_SEPOLIA,
    ARBITRUM_SEPOLIA,
    ROBINHOOD_TESTNET,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSupportRequirements {
    pub chain_id: u64,
    pub family: VerificationFamily,
    pub requires_ethereum_sepolia_bootstrap: bool,
    pub parent_chain_id: Option<u64>,
}

pub fn support_requirements(chain_id: u64) -> Option<ChainSupportRequirements> {
    let chain = chain_definition(chain_id)?;
    Some(ChainSupportRequirements {
        chain_id,
        family: chain.family,
        requires_ethereum_sepolia_bootstrap: true,
        parent_chain_id: chain.parent_chain_id,
    })
}

pub fn chain_definition(chain_id: u64) -> Option<&'static ChainDefinition> {
    SUPPORTED_CHAINS.iter().find(|chain| chain.chain_id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_poc_network_resolves_to_one_ethereum_bootstrap_dependency() {
        for chain in SUPPORTED_CHAINS {
            let requirements = support_requirements(chain.chain_id).unwrap();
            assert!(requirements.requires_ethereum_sepolia_bootstrap);
            if chain.chain_id == ETHEREUM_SEPOLIA_CHAIN_ID {
                assert_eq!(requirements.parent_chain_id, None);
            } else {
                assert_eq!(
                    requirements.parent_chain_id,
                    Some(ETHEREUM_SEPOLIA_CHAIN_ID)
                );
            }
        }
    }

    #[test]
    fn five_network_poc_has_three_verifier_families() {
        assert_eq!(SUPPORTED_CHAINS.len(), 5);
        assert_eq!(ETHEREUM_SEPOLIA.family, VerificationFamily::EthereumBeacon);
        assert_eq!(BASE_SEPOLIA.family, VerificationFamily::OpStack);
        assert_eq!(OP_SEPOLIA.family, VerificationFamily::OpStack);
        assert_eq!(ARBITRUM_SEPOLIA.family, VerificationFamily::Nitro);
        assert_eq!(ROBINHOOD_TESTNET.family, VerificationFamily::Nitro);
        assert!(
            SUPPORTED_CHAINS
                .iter()
                .filter(|chain| chain.parent_chain_id == Some(ETHEREUM_SEPOLIA_CHAIN_ID))
                .count()
                == 4
        );
    }
}
