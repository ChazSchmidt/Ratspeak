use ratspeak_eth_clearsign::DefinitionRegistry;
use ratspeak_eth_verifier::{VerificationFamily, chain_definition, support_requirements};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineReadiness {
    Ready,
    MissingChainSupport,
    MissingEthereumBootstrap,
    MissingAssetDefinitions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineReadinessReport {
    pub chain_id: u64,
    pub network: String,
    pub family: VerificationFamily,
    pub readiness: OfflineReadiness,
    pub ethereum_bootstrap_available: bool,
    pub clear_sign_definition_present: bool,
    pub balance_definition_present: bool,
}

impl OfflineReadinessReport {
    pub fn is_ready(&self) -> bool {
        self.readiness == OfflineReadiness::Ready
    }
}

pub fn assess_offline_readiness(
    chain_id: u64,
    ethereum_bootstrap_available: bool,
    definitions: &DefinitionRegistry,
    clear_sign_definition_id: Option<&str>,
    balance_definition_id: Option<&str>,
) -> OfflineReadinessReport {
    let Some(chain) = chain_definition(chain_id) else {
        return OfflineReadinessReport {
            chain_id,
            network: "unsupported".to_owned(),
            family: VerificationFamily::EthereumBeacon,
            readiness: OfflineReadiness::MissingChainSupport,
            ethereum_bootstrap_available,
            clear_sign_definition_present: false,
            balance_definition_present: false,
        };
    };

    let requirements = support_requirements(chain_id).expect("supported chain has requirements");
    let clear_sign_definition_present = clear_sign_definition_id
        .map(|id| definitions.contains(id))
        .unwrap_or(true);
    let balance_definition_present = balance_definition_id
        .map(|id| definitions.contains(id))
        .unwrap_or(true);

    let readiness = if requirements.requires_ethereum_sepolia_bootstrap
        && !ethereum_bootstrap_available
    {
        OfflineReadiness::MissingEthereumBootstrap
    } else if !clear_sign_definition_present || !balance_definition_present {
        OfflineReadiness::MissingAssetDefinitions
    } else {
        OfflineReadiness::Ready
    };

    OfflineReadinessReport {
        chain_id,
        network: chain.display_name.to_owned(),
        family: chain.family,
        readiness,
        ethereum_bootstrap_available,
        clear_sign_definition_present,
        balance_definition_present,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_eth_on_all_five_networks_is_one_click_ready_after_bootstrap() {
        let mut definitions = DefinitionRegistry::new();
        definitions.install_poc_native_definitions().unwrap();

        for chain_id in [11_155_111u64, 84_532, 11_155_420, 421_614, 46_630] {
            let report = assess_offline_readiness(
                chain_id,
                true,
                &definitions,
                None,
                None,
            );
            assert!(report.is_ready());
        }
    }

    #[test]
    fn missing_bootstrap_blocks_offline_readiness() {
        let definitions = DefinitionRegistry::new();
        let report = assess_offline_readiness(
            84_532,
            false,
            &definitions,
            None,
            None,
        );
        assert_eq!(report.readiness, OfflineReadiness::MissingEthereumBootstrap);
    }

    #[test]
    fn installed_asset_requires_both_internal_definitions() {
        let mut definitions = DefinitionRegistry::new();
        definitions
            .install_bytes(include_bytes!(
                "../../ratspeak-eth-clearsign/definitions/base-sepolia-usdc.json"
            ))
            .unwrap();

        let clear_id = definitions
            .ids()
            .find(|id| id.starts_with("erc7730-84532-"))
            .unwrap()
            .to_owned();
        let balance_id = "base-sepolia-usdc-balance-v1";

        let incomplete = assess_offline_readiness(
            84_532,
            true,
            &definitions,
            Some(&clear_id),
            Some(balance_id),
        );
        assert_eq!(
            incomplete.readiness,
            OfflineReadiness::MissingAssetDefinitions
        );

        definitions
            .install_bytes(include_bytes!(
                "../../ratspeak-eth-clearsign/definitions/base-sepolia-usdc-balance.json"
            ))
            .unwrap();

        let complete = assess_offline_readiness(
            84_532,
            true,
            &definitions,
            Some(&clear_id),
            Some(balance_id),
        );
        assert!(complete.is_ready());
    }
}
