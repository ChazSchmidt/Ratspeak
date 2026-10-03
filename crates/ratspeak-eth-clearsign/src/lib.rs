//! Offline clear-sign definition loading and operation decoding.
//!
//! This crate deliberately fails closed: an EVM operation is reviewable only
//! when one installed definition matches its chain, target, and semantics.

use std::fs;
use std::path::{Path, PathBuf};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use serde::Deserialize;

pub const BASE_CHAIN_ID: u64 = 8453;
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("definition JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("definition I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("definition is unsupported by this prototype: {0}")]
    UnsupportedDefinition(&'static str),
    #[error("definition address is invalid")]
    InvalidAddress,
    #[error("no trusted clear-sign definition matches this operation")]
    NoMatchingDefinition,
    #[error("more than one trusted clear-sign definition matches this operation")]
    AmbiguousDefinition,
    #[error("operation calldata is malformed")]
    MalformedCalldata,
    #[error("operation uses an unsupported function")]
    UnsupportedFunction,
    #[error("native definition cannot authorize calldata")]
    NativeCalldata,
    #[error("native transfer must use the 21,000 gas pure-value envelope")]
    UnsafeNativeGasLimit,
    #[error("ERC-20 transfer must not carry native value")]
    UnexpectedNativeValue,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmOperation {
    pub chain_id: u64,
    pub to: Address,
    pub value: U256,
    pub input: Bytes,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearSignReview {
    pub definition_id: String,
    pub definition_hash: B256,
    pub network: String,
    pub asset_symbol: String,
    pub asset_decimals: u8,
    pub recipient: Address,
    pub amount: U256,
    pub maximum_fee_wei: U256,
    pub operation_hash: B256,
    pub kind: ReviewKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewKind {
    NativeTransfer,
    Erc20Transfer,
}

#[derive(Clone, Debug)]
pub struct InstalledDefinition {
    raw: Vec<u8>,
    definition_hash: B256,
    definition_id: String,
    kind: DefinitionKind,
}

#[derive(Clone, Debug)]
enum DefinitionKind {
    Native(NativeDefinition),
    Erc7730(Erc7730Definition),
    Balance(BalanceDefinition),
}

#[derive(Clone, Debug)]
struct NativeDefinition {
    chain_id: u64,
    network: String,
    symbol: String,
    decimals: u8,
    #[serde(default)]
    contract: Option<String>,
    #[serde(default)]
    storage: Option<RawBalanceStorage>,
}

#[derive(Debug, Deserialize)]
struct RawBalanceStorage {
    #[serde(rename = "mappingSlot")]
    mapping_slot: u64,
    #[serde(rename = "valueMaskBits")]
    value_mask_bits: u16,
}

#[derive(Clone, Debug)]
struct Erc7730Definition {
    chain_id: u64,
    contract: Address,
    network: String,
    symbol: String,
    decimals: u8,
    selector: [u8; 4],
}

#[derive(Clone, Debug)]
struct BalanceDefinition {
    chain_id: u64,
    contract: Address,
    network: String,
    symbol: String,
    decimals: u8,
    mapping_slot: U256,
    value_mask_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceProofQuery {
    pub definition_id: String,
    pub chain_id: u64,
    pub contract: Address,
    pub network: String,
    pub symbol: String,
    pub decimals: u8,
    pub storage_key: B256,
    pub value_mask_bits: u16,
}

impl BalanceProofQuery {
    pub fn interpret_storage_value(&self, value: U256) -> U256 {
        if self.value_mask_bits >= 256 {
            return value;
        }
        let mask = (U256::from(1u8) << self.value_mask_bits) - U256::from(1u8);
        value & mask
    }
}

#[derive(Debug, Deserialize)]
struct RawDefinition {
    #[serde(default, rename = "$schema")]
    schema: Option<String>,
    #[serde(default)]
    ratspeak: Option<RawRatspeak>,
    #[serde(default)]
    context: Option<RawContext>,
    #[serde(default)]
    display: Option<RawDisplay>,
    #[serde(default)]
    metadata: Option<RawMetadata>,
}

#[derive(Debug, Deserialize)]
struct RawRatspeak {
    #[serde(rename = "definitionId")]
    definition_id: String,
    kind: String,
    #[serde(rename = "chainId")]
    chain_id: u64,
    network: String,
    symbol: String,
    decimals: u8,
}

#[derive(Debug, Deserialize)]
struct RawContext {
    contract: RawContractContext,
}

#[derive(Debug, Deserialize)]
struct RawContractContext {
    deployments: Vec<RawDeployment>,
}

#[derive(Debug, Deserialize)]
struct RawDeployment {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
}

#[derive(Debug, Deserialize)]
struct RawDisplay {
    formats: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default, rename = "contractName")]
    contract_name: Option<String>,
    token: Option<TokenMeta>,
}

#[derive(Debug, Deserialize)]
struct TokenMeta {
    name: String,
    ticker: String,
    decimals: u8,
}

impl InstalledDefinition {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw: RawDefinition = serde_json::from_slice(bytes)?;
        let definition_hash = keccak256(bytes);

        if let Some(native) = raw.ratspeak {
            if native.definition_id.is_empty()
                || !native
                    .definition_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Error::UnsupportedDefinition(
                    "RatSpeak definition id contains unsafe characters",
                ));
            }
            match native.kind.as_str() {
                "nativeTransfer" => {
                    return Ok(Self {
                        raw: bytes.to_vec(),
                        definition_hash,
                        definition_id: native.definition_id,
                        kind: DefinitionKind::Native(NativeDefinition {
                            chain_id: native.chain_id,
                            network: native.network,
                            symbol: native.symbol,
                            decimals: native.decimals,
                        }),
                    });
                }
                "erc20Balance" => {
                    let contract: Address = native
                        .contract
                        .ok_or(Error::UnsupportedDefinition(
                            "balance definition is missing contract",
                        ))?
                        .parse()
                        .map_err(|_| Error::InvalidAddress)?;
                    let storage = native.storage.ok_or(Error::UnsupportedDefinition(
                        "balance definition is missing storage layout",
                    ))?;
                    if storage.value_mask_bits == 0 || storage.value_mask_bits > 256 {
                        return Err(Error::UnsupportedDefinition(
                            "balance definition has invalid value mask",
                        ));
                    }
                    return Ok(Self {
                        raw: bytes.to_vec(),
                        definition_hash,
                        definition_id: native.definition_id,
                        kind: DefinitionKind::Balance(BalanceDefinition {
                            chain_id: native.chain_id,
                            contract,
                            network: native.network,
                            symbol: native.symbol,
                            decimals: native.decimals,
                            mapping_slot: U256::from(storage.mapping_slot),
                            value_mask_bits: storage.value_mask_bits,
                        }),
                    });
                }
                _ => {
                    return Err(Error::UnsupportedDefinition(
                        "unknown RatSpeak definition kind",
                    ));
                }
            }
        }

        if raw.schema.as_deref()
            != Some("https://eips.ethereum.org/assets/eip-7730/erc7730-v2.schema.json")
        {
            return Err(Error::UnsupportedDefinition(
                "ERC-7730 v2 schema marker required",
            ));
        }
        let context = raw
            .context
            .ok_or(Error::UnsupportedDefinition("missing context.contract"))?;
        if context.contract.deployments.len() != 1 {
            return Err(Error::UnsupportedDefinition(
                "prototype requires exactly one deployment",
            ));
        }
        let deployment = &context.contract.deployments[0];
        let contract: Address = deployment
            .address
            .parse()
            .map_err(|_| Error::InvalidAddress)?;
        let display = raw
            .display
            .ok_or(Error::UnsupportedDefinition("missing display.formats"))?;
        if display.formats.len() != 1 {
            return Err(Error::UnsupportedDefinition(
                "prototype requires exactly one function format",
            ));
        }
        let (fragment, format) = display.formats.iter().next().unwrap();
        let canonical = canonical_signature(fragment)?;
        let selector_hash = keccak256(canonical.as_bytes());
        let selector = [
            selector_hash[0],
            selector_hash[1],
            selector_hash[2],
            selector_hash[3],
        ];
        if selector != ERC20_TRANSFER_SELECTOR || canonical != "transfer(address,uint256)" {
            return Err(Error::UnsupportedDefinition(
                "only ERC-20 transfer(address,uint256) is supported",
            ));
        }
        validate_transfer_format(format)?;

        let metadata = raw
            .metadata
            .ok_or(Error::UnsupportedDefinition("missing metadata"))?;
        let token = metadata
            .token
            .ok_or(Error::UnsupportedDefinition("missing metadata.token"))?;
        if token.name.trim().is_empty() || token.ticker.trim().is_empty() {
            return Err(Error::UnsupportedDefinition(
                "token metadata must include name and ticker",
            ));
        }
        let _ = metadata.owner;
        let _ = metadata.contract_name;
        let definition_id = format!(
            "erc7730-{}-{}-{:02x}{:02x}{:02x}{:02x}",
            deployment.chain_id,
            alloy_primitives::hex::encode(contract.as_slice()),
            selector[0],
            selector[1],
            selector[2],
            selector[3]
        );

        Ok(Self {
            raw: bytes.to_vec(),
            definition_hash,
            definition_id,
            kind: DefinitionKind::Erc7730(Erc7730Definition {
                chain_id: deployment.chain_id,
                contract,
                network: network_label(deployment.chain_id),
                symbol: token.ticker,
                decimals: token.decimals,
                selector,
            }),
        })
    }

    pub fn definition_id(&self) -> &str {
        &self.definition_id
    }
    pub fn definition_hash(&self) -> B256 {
        self.definition_hash
    }
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn review(&self, op: &EvmOperation) -> Result<Option<ClearSignReview>> {
        let maximum_fee_wei = U256::from(op.gas_limit)
            .checked_mul(U256::from(op.max_fee_per_gas))
            .ok_or(Error::MalformedCalldata)?;
        let operation_hash = hash_operation(op);

        match &self.kind {
            DefinitionKind::Native(d) => {
                if op.chain_id != d.chain_id {
                    return Ok(None);
                }
                if !op.input.is_empty() {
                    return Ok(None);
                }
                if op.gas_limit != 21_000 {
                    return Err(Error::UnsafeNativeGasLimit);
                }
                if op.value == U256::ZERO {
                    return Ok(None);
                }
                Ok(Some(ClearSignReview {
                    definition_id: self.definition_id.clone(),
                    definition_hash: self.definition_hash,
                    network: d.network.clone(),
                    asset_symbol: d.symbol.clone(),
                    asset_decimals: d.decimals,
                    recipient: op.to,
                    amount: op.value,
                    maximum_fee_wei,
                    operation_hash,
                    kind: ReviewKind::NativeTransfer,
                }))
            }
            DefinitionKind::Balance(_) => Ok(None),
            DefinitionKind::Erc7730(d) => {
                if op.chain_id != d.chain_id || op.to != d.contract {
                    return Ok(None);
                }
                if op.value != U256::ZERO {
                    return Err(Error::UnexpectedNativeValue);
                }
                if op.input.len() < 4 {
                    return Err(Error::MalformedCalldata);
                }
                if op.input[..4] != d.selector {
                    return Err(Error::UnsupportedFunction);
                }
                if op.input.len() != 68 {
                    return Err(Error::MalformedCalldata);
                }
                if op.input[4..16].iter().any(|b| *b != 0) {
                    return Err(Error::MalformedCalldata);
                }
                let recipient = Address::from_slice(&op.input[16..36]);
                let amount = U256::from_be_slice(&op.input[36..68]);
                Ok(Some(ClearSignReview {
                    definition_id: self.definition_id.clone(),
                    definition_hash: self.definition_hash,
                    network: d.network.clone(),
                    asset_symbol: d.symbol.clone(),
                    asset_decimals: d.decimals,
                    recipient,
                    amount,
                    maximum_fee_wei,
                    operation_hash,
                    kind: ReviewKind::Erc20Transfer,
                }))
            }
        }
    }
}

fn validate_transfer_format(value: &serde_json::Value) -> Result<()> {
    let intent = value.get("intent").and_then(|v| v.as_str());
    let fields = value.get("fields").and_then(|v| v.as_array());
    if intent != Some("Send") {
        return Err(Error::UnsupportedDefinition("transfer intent must be Send"));
    }
    let fields = fields.ok_or(Error::UnsupportedDefinition("transfer fields missing"))?;
    let has_to = fields.iter().any(|f| {
        f.get("path").and_then(|v| v.as_str()) == Some("to")
            && f.get("format").and_then(|v| v.as_str()) == Some("addressName")
    });
    let has_value = fields.iter().any(|f| {
        f.get("path").and_then(|v| v.as_str()) == Some("value")
            && f.get("format").and_then(|v| v.as_str()) == Some("tokenAmount")
    });
    if !has_to || !has_value {
        return Err(Error::UnsupportedDefinition(
            "transfer definition must display recipient and token amount",
        ));
    }
    Ok(())
}

fn canonical_signature(fragment: &str) -> Result<String> {
    let open = fragment
        .find('(')
        .ok_or(Error::UnsupportedDefinition("invalid ABI fragment"))?;
    let close = fragment
        .rfind(')')
        .ok_or(Error::UnsupportedDefinition("invalid ABI fragment"))?;
    if close <= open {
        return Err(Error::UnsupportedDefinition("invalid ABI fragment"));
    }
    let name = &fragment[..open];
    let params = &fragment[open + 1..close];
    let mut types = Vec::new();
    for param in params.split(',') {
        let ty = param
            .split_whitespace()
            .next()
            .ok_or(Error::UnsupportedDefinition("invalid ABI parameter"))?;
        types.push(ty);
    }
    Ok(format!("{name}({})", types.join(",")))
}

fn network_label(chain_id: u64) -> String {
    match chain_id {
        1 => "Ethereum".to_owned(),
        BASE_CHAIN_ID => "Base".to_owned(),
        BASE_SEPOLIA_CHAIN_ID => "Base Sepolia".to_owned(),
        11_155_111 => "Sepolia".to_owned(),
        other => format!("EIP-155 {other}"),
    }
}

pub fn hash_operation(op: &EvmOperation) -> B256 {
    let mut bytes = Vec::with_capacity(128 + op.input.len());
    bytes.extend_from_slice(b"ratspeak.ethereum.clearsign-operation.v1\0");
    bytes.extend_from_slice(&op.chain_id.to_be_bytes());
    bytes.extend_from_slice(op.to.as_slice());
    bytes.extend_from_slice(&op.value.to_be_bytes::<32>());
    bytes.extend_from_slice(&op.gas_limit.to_be_bytes());
    bytes.extend_from_slice(&op.max_fee_per_gas.to_be_bytes());
    bytes.extend_from_slice(&op.max_priority_fee_per_gas.to_be_bytes());
    bytes.extend_from_slice(&(op.input.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&op.input);
    keccak256(bytes)
}

#[derive(Default)]
pub struct DefinitionRegistry {
    definitions: Vec<InstalledDefinition>,
}

impl DefinitionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install_bytes(&mut self, bytes: &[u8]) -> Result<B256> {
        let definition = InstalledDefinition::parse(bytes)?;
        let hash = definition.definition_hash();
        self.definitions
            .retain(|d| d.definition_id() != definition.definition_id());
        self.definitions.push(definition);
        Ok(hash)
    }

    pub fn remove(&mut self, definition_id: &str) -> bool {
        let before = self.definitions.len();
        self.definitions
            .retain(|d| d.definition_id() != definition_id);
        before != self.definitions.len()
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.definitions.iter().map(|d| d.definition_id())
    }

    pub fn review(&self, operation: &EvmOperation) -> Result<ClearSignReview> {
        let mut matches = Vec::new();
        let mut hard_error = None;
        for definition in &self.definitions {
            match definition.review(operation) {
                Ok(Some(review)) => matches.push(review),
                Ok(None) => {}
                Err(error) => hard_error = Some(error),
            }
        }
        if matches.len() > 1 {
            return Err(Error::AmbiguousDefinition);
        }
        if let Some(review) = matches.pop() {
            return Ok(review);
        }
        if let Some(error) = hard_error {
            return Err(error);
        }
        Err(Error::NoMatchingDefinition)
    }

    pub fn balance_query(
        &self,
        definition_id: &str,
        owner: Address,
    ) -> Result<BalanceProofQuery> {
        let definition = self
            .definitions
            .iter()
            .find(|definition| definition.definition_id() == definition_id)
            .ok_or(Error::NoMatchingDefinition)?;
        let DefinitionKind::Balance(balance) = &definition.kind else {
            return Err(Error::UnsupportedDefinition(
                "definition is not a balance-proof definition",
            ));
        };

        let mut encoded = [0u8; 64];
        encoded[12..32].copy_from_slice(owner.as_slice());
        encoded[32..64].copy_from_slice(&balance.mapping_slot.to_be_bytes::<32>());
        Ok(BalanceProofQuery {
            definition_id: definition.definition_id.clone(),
            chain_id: balance.chain_id,
            contract: balance.contract,
            network: balance.network.clone(),
            symbol: balance.symbol.clone(),
            decimals: balance.decimals,
            storage_key: keccak256(encoded),
            value_mask_bits: balance.value_mask_bits,
        })
    }

    pub fn load_dir(path: &Path) -> Result<Self> {
        let mut registry = Self::new();
        if !path.exists() {
            return Ok(registry);
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        entries.sort();
        for entry in entries {
            registry.install_bytes(&fs::read(entry)?)?;
        }
        Ok(registry)
    }

    pub fn install_file(store: &Path, source: &Path) -> Result<B256> {
        let bytes = fs::read(source)?;
        let definition = InstalledDefinition::parse(&bytes)?;
        fs::create_dir_all(store)?;
        let destination = store.join(format!("{}.json", definition.definition_id()));
        let temporary = store.join(format!(".{}.tmp", definition.definition_id()));
        fs::write(&temporary, &bytes)?;
        fs::rename(temporary, destination)?;
        Ok(definition.definition_hash())
    }

    pub fn remove_file(store: &Path, definition_id: &str) -> Result<bool> {
        let path = store.join(format!("{definition_id}.json"));
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NATIVE: &[u8] = include_bytes!("../definitions/base-native-eth.json");
    const USDC: &[u8] = include_bytes!("../definitions/base-usdc.json");
    const ALUSDB: &[u8] = include_bytes!("../definitions/base-alusdb.json");
    const RATSPEAK: &[u8] = include_bytes!("../definitions/base-ratspeak.json");
    const BASE_SEPOLIA_NATIVE: &[u8] = include_bytes!("../definitions/base-sepolia-native-eth.json");
    const BASE_SEPOLIA_USDC: &[u8] = include_bytes!("../definitions/base-sepolia-usdc.json");

    fn address(s: &str) -> Address {
        s.parse().unwrap()
    }

    fn transfer_input(to: Address, amount: U256) -> Bytes {
        let mut input = Vec::with_capacity(68);
        input.extend_from_slice(&ERC20_TRANSFER_SELECTOR);
        input.extend_from_slice(&[0u8; 12]);
        input.extend_from_slice(to.as_slice());
        input.extend_from_slice(&amount.to_be_bytes::<32>());
        input.into()
    }

    fn op(contract: &str, input: Bytes) -> EvmOperation {
        EvmOperation {
            chain_id: BASE_CHAIN_ID,
            to: address(contract),
            value: U256::ZERO,
            input,
            gas_limit: 65_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
        }
    }

    fn registry() -> DefinitionRegistry {
        let mut r = DefinitionRegistry::new();
        for d in [NATIVE, USDC, ALUSDB, RATSPEAK, BASE_SEPOLIA_NATIVE, BASE_SEPOLIA_USDC] {
            r.install_bytes(d).unwrap();
        }
        r
    }

    #[test]
    fn base_sepolia_native_eth_transfer_is_clear_signed() {
        let r = registry();
        let op = EvmOperation {
            chain_id: BASE_SEPOLIA_CHAIN_ID,
            to: address("1111111111111111111111111111111111111111"),
            value: U256::from(10_000_000_000_000_000u64),
            input: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
        };
        let review = r.review(&op).unwrap();
        assert_eq!(review.asset_symbol, "ETH");
        assert_eq!(review.network, "Base Sepolia");
        assert_eq!(review.recipient, op.to);
        assert_eq!(review.kind, ReviewKind::NativeTransfer);
    }

    #[test]
    fn base_sepolia_usdc_uses_same_erc20_decoder() {
        let recipient = address("2222222222222222222222222222222222222222");
        let review = registry()
            .review(&EvmOperation {
                chain_id: BASE_SEPOLIA_CHAIN_ID,
                to: address("036CbD53842c5426634e7929541eC2318f3dCF7e"),
                value: U256::ZERO,
                input: transfer_input(recipient, U256::from(10_000_000u64)),
                gas_limit: 65_000,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 100_000_000,
            })
            .unwrap();
        assert_eq!(review.asset_symbol, "USDC");
        assert_eq!(review.asset_decimals, 6);
        assert_eq!(review.network, "Base Sepolia");
        assert_eq!(review.recipient, recipient);
        assert_eq!(review.amount, U256::from(10_000_000u64));
    }

    #[test]
    fn native_eth_transfer_is_clear_signed() {
        let r = registry();
        let op = EvmOperation {
            chain_id: BASE_CHAIN_ID,
            to: address("1111111111111111111111111111111111111111"),
            value: U256::from(10_000_000_000_000_000u64),
            input: Bytes::new(),
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
        };
        let review = r.review(&op).unwrap();
        assert_eq!(review.asset_symbol, "ETH");
        assert_eq!(review.recipient, op.to);
        assert_eq!(review.kind, ReviewKind::NativeTransfer);
    }

    #[test]
    fn native_eth_rejects_contract_execution_sized_gas() {
        let r = registry();
        let operation = EvmOperation {
            chain_id: BASE_CHAIN_ID,
            to: address("1111111111111111111111111111111111111111"),
            value: U256::from(1u64),
            input: Bytes::new(),
            gas_limit: 50_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
        };
        assert!(matches!(
            r.review(&operation),
            Err(Error::UnsafeNativeGasLimit)
        ));
    }

    #[test]
    fn all_three_erc20_definitions_share_one_decoder() {
        let recipient = address("2222222222222222222222222222222222222222");
        for (contract, symbol, amount) in [
            (
                "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "USDC",
                U256::from(10_000_000u64),
            ),
            (
                "877014E21c32feA108B6A1f45f367efc9a2d9B9F",
                "alUSDb",
                U256::from(5_000_000_000_000_000_000u64),
            ),
            (
                "f1e9Baa65d418A9025e1851DD2D37f1AD208bba3",
                "RATSPEAK",
                U256::from(100_000u64) * U256::from(1_000_000_000_000_000_000u128),
            ),
        ] {
            let review = registry()
                .review(&op(contract, transfer_input(recipient, amount)))
                .unwrap();
            assert_eq!(review.asset_symbol, symbol);
            assert_eq!(review.recipient, recipient);
            assert_eq!(review.amount, amount);
        }
    }

    #[test]
    fn unknown_contract_and_chain_fail_closed() {
        let recipient = address("2222222222222222222222222222222222222222");
        let r = registry();
        assert!(matches!(
            r.review(&op(
                "3333333333333333333333333333333333333333",
                transfer_input(recipient, U256::from(1))
            )),
            Err(Error::NoMatchingDefinition)
        ));
        let mut wrong_chain = op(
            "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            transfer_input(recipient, U256::from(1)),
        );
        wrong_chain.chain_id = 1;
        assert!(matches!(
            r.review(&wrong_chain),
            Err(Error::NoMatchingDefinition)
        ));
    }

    #[test]
    fn approve_is_rejected() {
        let r = registry();
        let mut input = vec![0x09, 0x5e, 0xa7, 0xb3];
        input.resize(68, 0);
        assert!(matches!(
            r.review(&op(
                "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                input.into()
            )),
            Err(Error::UnsupportedFunction)
        ));
    }

    #[test]
    fn recipient_and_amount_mutations_change_operation_hash() {
        let r = registry();
        let a = address("2222222222222222222222222222222222222222");
        let b = address("3333333333333333333333333333333333333333");
        let one = op(
            "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            transfer_input(a, U256::from(10_000_000u64)),
        );
        let recipient_changed = op(
            "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            transfer_input(b, U256::from(10_000_000u64)),
        );
        let amount_changed = op(
            "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            transfer_input(a, U256::from(11_000_000u64)),
        );
        let x = r.review(&one).unwrap();
        assert_ne!(
            x.operation_hash,
            r.review(&recipient_changed).unwrap().operation_hash
        );
        assert_ne!(
            x.operation_hash,
            r.review(&amount_changed).unwrap().operation_hash
        );
    }

    #[test]
    fn definitions_install_load_and_remove_from_directory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let store = std::env::temp_dir().join(format!(
            "ratspeak-clearsign-{}-{unique}",
            std::process::id()
        ));
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("definitions/base-usdc.json");

        DefinitionRegistry::install_file(&store, &source).unwrap();
        let loaded = DefinitionRegistry::load_dir(&store).unwrap();
        assert!(
            loaded
                .ids()
                .any(|id| id == "erc7730-8453-833589fcd6edb6e08f4c7c32d4f71b54bda02913-a9059cbb")
        );

        let recipient = address("2222222222222222222222222222222222222222");
        assert!(
            loaded
                .review(&op(
                    "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    transfer_input(recipient, U256::from(1_000_000u64)),
                ))
                .is_ok()
        );

        assert!(
            DefinitionRegistry::remove_file(
                &store,
                "erc7730-8453-833589fcd6edb6e08f4c7c32d4f71b54bda02913-a9059cbb"
            )
            .unwrap()
        );
        let reloaded = DefinitionRegistry::load_dir(&store).unwrap();
        assert!(matches!(
            reloaded.review(&op(
                "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                transfer_input(recipient, U256::from(1_000_000u64)),
            )),
            Err(Error::NoMatchingDefinition)
        ));

        let _ = fs::remove_dir_all(store);
    }

    #[test]
    fn removing_definition_makes_operation_unsignable() {
        let recipient = address("2222222222222222222222222222222222222222");
        let mut r = registry();
        assert!(r.remove("erc7730-8453-833589fcd6edb6e08f4c7c32d4f71b54bda02913-a9059cbb"));
        assert!(matches!(
            r.review(&op(
                "833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                transfer_input(recipient, U256::from(1))
            )),
            Err(Error::NoMatchingDefinition)
        ));
    }
}
