use std::{sync::Arc, fs};

use rand_core::SeedableRng as _;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;
use ciphersuite::{group::ff::PrimeField as _, WrappedGroup, WithPreferredHash};
use dalek_ff_group::Ristretto;
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

use sp_core::{
  Encode as _, Decode as _, Pair as _,
  sr25519::Pair,
  traits::{RuntimeCode, WrappedRuntimeCode, CallContext, CodeExecutor as _},
};
use sp_runtime::{
  Digest,
  traits::{Block as _, Header as _},
};
use sp_state_machine::BasicExternalities;
use sp_io::SubstrateHostFunctions;

use serai_abi::{
  primitives::{prelude::*, crypto::SignedEmbeddedEllipticCurveKeys},
  SubstrateBlock as Block,
};
use serai_runtime::GenesisConfig;

use sc_client_db::{BlockImportOperation, Backend};
use sc_executor::{RuntimeVersionOf, WasmExecutor};
use sc_chain_spec::{BuildGenesisBlock, GenesisBlockBuilder, ChainSpecBuilder};
use sc_service::{ChainType, ChainSpec as _, GenericChainSpec as ChainSpec};

use serai_env::Environment;

/// Generate the key pair for the validator corresponding to a development seed.
///
/// This is insecure and MUST NOT be used except testing purposes.
///
/// Note the development seed itself is used as the _auxiliary key_ used to operate the node with.
pub(super) fn validator_identity_for_dev_seed(dev_seed: &str) -> SeraiAddress {
  Pair::from_seed(&sp_crypto_hashing::blake2_256(dev_seed.as_bytes())).public().into()
}

/// Create an insecure key pair from a name alone.
///
/// This will have effectively no entropy and MUST NOT be used except for testing purposes.
fn insecure_keypair_from_name(name: &'static str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

/// Create an insecure Serai address (with known private key) from a name alone.
///
/// This will have effectively no entropy and MUST NOT be used except for testing purposes.
fn insecure_account_from_name(name: &'static str) -> SeraiAddress {
  Pair::from_seed(&sp_crypto_hashing::blake2_256(format!("//{name}").as_bytes())).public().into()
}

/// Create an insecure key for a curve from a name alone, which whoever runs the validator's
/// processors can compute too.
///
/// This will have effectively no entropy and MUST NOT be used except for testing purposes.
fn insecure_arbitrary_key_from_name<C: WithPreferredHash>(name: &str) -> C::F {
  C::hash_to_F([b"insecure arbitrary key".as_slice(), name.as_bytes()].concat())
}

/// Create a list of insecure auxiliary keys for the specified validator.
///
/// Every node builds genesis itself (`local_config`), so these, and the signatures' randomness, are
/// all from the validator's name: drawn from `OsRng`, each node built a genesis of its own, and
/// four nodes couldn't join one chain. The external networks' keys are ones the processors can be
/// given (`insecure_arbitrary_key_from_name`), as no one could hold random ones.
fn insecure_auxiliary_keys(name: &'static str) -> Vec<SignedEmbeddedEllipticCurveKeys> {
  let validator = insecure_account_from_name(name);
  let mut rng = ChaCha20Rng::from_seed(sp_crypto_hashing::blake2_256(
    format!("auxiliary-keys-//{name}").as_bytes(),
  ));
  let embedwards = || Zeroizing::new(insecure_arbitrary_key_from_name::<Embedwards25519>(name));
  let secq = || Zeroizing::new(insecure_arbitrary_key_from_name::<Secq256k1>(name));
  vec![
    SignedEmbeddedEllipticCurveKeys::serai(
      &mut rng,
      validator,
      &Zeroizing::new(
        <Ristretto as WrappedGroup>::F::from_repr(
          insecure_keypair_from_name(name).to_raw_vec()[.. 32].try_into().unwrap(),
        )
        .unwrap(),
      ),
    ),
    SignedEmbeddedEllipticCurveKeys::bitcoin(&mut rng, validator, &embedwards(), &secq()),
    SignedEmbeddedEllipticCurveKeys::ethereum(&mut rng, validator, &embedwards(), &secq()),
    SignedEmbeddedEllipticCurveKeys::monero(&mut rng, validator, &embedwards()),
  ]
}

fn wasm_binary(env: Option<&Environment>, dev: bool) -> Vec<u8> {
  const DEFAULT_WASM_PATH: &str = "/runtime/serai.wasm";
  let path = env
    .and_then(|env| env.var("SERAI_WASM_PATH").map(|path| (**path).clone()))
    .unwrap_or(DEFAULT_WASM_PATH.to_owned());
  if let Ok(binary) = fs::read(&path) {
    sp_tracing::info!("using {} for the WASM", &*path);
    return binary;
  }

  assert!(dev, "could not read WASM for the runtime and this is not a dev network");

  sp_tracing::info!("using built-in wasm");
  serai_runtime::WASM.to_vec()
}

fn devnet_genesis(
  validators: &[&'static str],
  endowed_accounts: Vec<SeraiAddress>,
) -> GenesisConfig {
  GenesisConfig {
    validators: validators
      .iter()
      .map(|name| (insecure_account_from_name(name), insecure_auxiliary_keys(name)))
      .collect(),
    fees: vec![
      (ExternalCoin::Bitcoin, 2),
      (ExternalCoin::Ether, 2),
      (ExternalCoin::Dai, 2),
      (ExternalCoin::Monero, 15),
    ],
    coins: endowed_accounts
      .into_iter()
      .map(|address| (address, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
      .collect(),
  }
}

/// Call Serai's genesis API, used to initialize the on-chain storage.
fn genesis(
  env: Option<&Environment>,
  name: &'static str,
  id: &'static str,
  chain_type: ChainType,
  protocol_id: &'static str,
  config: &GenesisConfig,
) -> ChainSpec {
  let bin = wasm_binary(env, matches!(chain_type, ChainType::Development));
  let hash = sp_crypto_hashing::blake2_256(&bin).to_vec();

  let mut chain_spec = ChainSpecBuilder::new(&bin, None)
    .with_name(name)
    .with_id(id)
    .with_chain_type(chain_type)
    .with_protocol_id(protocol_id)
    .build();

  let mut ext = BasicExternalities::new_empty();
  let code_fetcher = WrappedRuntimeCode(bin.clone().into());
  WasmExecutor::<SubstrateHostFunctions>::builder()
    .build()
    .call(
      &mut ext,
      &RuntimeCode { code_fetcher: &code_fetcher, heap_pages: None, hash },
      "GenesisApi_build",
      &config.encode(),
      CallContext::Onchain {
        // We set import as true as this effectively is 'importing' the genesis block
        import: true,
      },
    )
    .0
    .unwrap();
  let mut storage = ext.into_storages();
  storage.top.insert(sp_core::storage::well_known_keys::CODE.to_vec(), bin);
  chain_spec.set_storage(storage);

  chain_spec
}

pub(super) fn solo_config(env: Option<&Environment>) -> ChainSpec {
  genesis(
    env,
    "Solo Network",
    "solo",
    ChainType::Development,
    "serai-solo",
    &devnet_genesis(
      &["Alice"],
      vec![
        insecure_account_from_name("Alice"),
        insecure_account_from_name("Bob"),
        insecure_account_from_name("Charlie"),
        insecure_account_from_name("Dave"),
        insecure_account_from_name("Eve"),
      ],
    ),
  )
}

/// Testing only (the `testnet` feature): the test network's own account, endowed beside the
/// development accounts, read from `SERAI_TEST_ACCOUNT` as a Serai address.
///
/// The development accounts' keys are public, so on a network others use, anyone could spend what
/// they hold. A node built with the feature refuses to start without this account, with one that
/// isn't a Serai address, or with one of the development accounts.
#[cfg(feature = "testnet")]
fn testnet_account(development: &[SeraiAddress]) -> SeraiAddress {
  let account = std::env::var("SERAI_TEST_ACCOUNT").unwrap_or_else(|_| {
    panic!(
      "built with the testnet feature: set SERAI_TEST_ACCOUNT to the test network's own Serai \
       address"
    )
  });
  let address: SeraiAddress = account
    .parse()
    .unwrap_or_else(|e| panic!("SERAI_TEST_ACCOUNT isn't a Serai address ({e:?}): {account}"));
  assert!(
    !development.contains(&address),
    "SERAI_TEST_ACCOUNT is a development account, whose key is public: {account}"
  );
  address
}

pub(super) fn local_config(env: Option<&Environment>) -> ChainSpec {
  #[cfg_attr(not(feature = "testnet"), expect(unused_mut))]
  let mut endowed = vec![
    insecure_account_from_name("Alice"),
    insecure_account_from_name("Bob"),
    insecure_account_from_name("Charlie"),
    insecure_account_from_name("Dave"),
    insecure_account_from_name("Eve"),
  ];
  // Testing only: the test network's own account, beside the development accounts
  #[cfg(feature = "testnet")]
  {
    let account = testnet_account(&endowed);
    endowed.push(account);
  }
  genesis(
    env,
    "Local Test Network",
    "local",
    ChainType::Local,
    "serai-local",
    &devnet_genesis(&["Alice", "Bob", "Charlie", "Dave"], endowed),
  )
}

/// Construct Serai's genesis block.
struct GenesisBlock<Executor> {
  /// The underlying genesis block builder from Substrate.
  builder: GenesisBlockBuilder<Block, Backend<Block>, Executor>,
  /// The `Digest`, which we want with the genesis block but must keep track of ourselves.
  digest: Digest,
}
impl<Executor: RuntimeVersionOf> BuildGenesisBlock<Block> for GenesisBlock<Executor> {
  type BlockImportOperation = BlockImportOperation<Block>;

  fn build_genesis_block(
    self,
  ) -> Result<(Block, Self::BlockImportOperation), sp_blockchain::Error> {
    let Self { builder, digest } = self;

    let (genesis_block, op) = builder.build_genesis_block()?;

    // Attach the digest to the yielded block's header now
    let genesis_block = {
      let (mut header, transactions) = genesis_block.deconstruct();
      *header.digest_mut() = digest;
      Block::new(header, transactions)
    };

    Ok((genesis_block, op))
  }
}

/// Construct the genesis block for Serai.
pub(super) fn genesis_block(
  chain_spec: &dyn sc_chain_spec::ChainSpec,
  backend: Arc<Backend<Block>>,
  executor: impl RuntimeVersionOf,
) -> Result<
  impl BuildGenesisBlock<Block, BlockImportOperation = BlockImportOperation<Block>>,
  sc_service::error::Error,
> {
  let storage = chain_spec.as_storage_builder().build_storage()?;
  // Manually extract the `Digest` from `frame-system` as Substrate won't yield it for us
  // TODO: While this is technically fine, it'd be better to use a `RuntimeApi`
  let digest = {
    let digest_key =
      [sp_crypto_hashing::twox_128(b"System"), sp_crypto_hashing::twox_128(b"Digest")].concat();
    Digest::decode(&mut storage.top.get(&digest_key).expect("`System Digest` not set").as_slice())
      .expect("failed to decode `System Digest`")
  };

  let commit_genesis_state = true;
  Ok(GenesisBlock {
    builder: GenesisBlockBuilder::new_with_storage(
      storage,
      commit_genesis_state,
      backend,
      executor,
    )?,
    digest,
  })
}
