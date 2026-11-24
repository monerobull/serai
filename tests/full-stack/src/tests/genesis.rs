//! Completes the genesis liquidity period for the local test network.
//!
//! The genesis liquidity of every external network is expected to come from real deposits made
//! through the processors (with `InInstruction::GenesisLiquidity`). Forging their batches isn't
//! possible (their keys are set by the real DKG) and would poison the processors' state if it
//! were.
//!
//! The helpers here are largely copied from `substrate/client/serai/tests/common/mod.rs`.

use core::time::Duration;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{group::GroupEncoding as _, GroupIo, WrappedGroup as _};
use musig::{Participant, ThresholdKeys, musig};
use dalek_ff_group::Ristretto;
use schnorrkel::Schnorrkel;

use sp_core::{Pair as _, sr25519::Pair};
use sp_application_crypto::RuntimePublic as _;

use serai_client_serai::{
  Serai,
  abi::{
    Call, Transaction,
    genesis_liquidity::Call as GenesisLiquidityCall,
    primitives::{
      balance::Amount,
      coin::ExternalCoin,
      crypto::RistrettoSignature,
      genesis_liquidity::GenesisValues,
      network_id::NetworkId,
      validator_sets::{Session, ValidatorSet},
    },
  },
};

/// The validators of the `local` chain config, in genesis (chain-spec) order.
const VALIDATOR_NAMES: [&str; 4] = ["Alice", "Bob", "Charlie", "Dave"];

fn insecure_pair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

/// The dev validators' key pairs, in the order their auxiliary keys appear in
/// `GenesisValidatorsAuxiliaryKeys` (the genesis order).
fn dev_pairs_in_genesis_order() -> Vec<Pair> {
  VALIDATOR_NAMES.iter().map(|name| insecure_pair_from_name(name)).collect()
}

/// Ask Serai's node until it answers, saying so each time it doesn't. One failed answer used to
/// stop the test, and the test's teardown removes the whole network (specification 32).
async fn ask<T, E: core::fmt::Debug, F: core::future::Future<Output = Result<T, E>>>(
  what: &str,
  mut question: impl FnMut() -> F,
) -> T {
  loop {
    match question().await {
      Ok(answer) => return answer,
      Err(e) => {
        println!("Serai's node didn't answer {what} ({e:?}); trying again in 5s");
        tokio::time::sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

/// Whether genesis completed, asked until the node answers.
#[expect(closure_returning_async_block)]
async fn genesis_completed(serai: &Serai) -> bool {
  ask(
    "whether genesis completed",
    move || async move { serai.state().await?.genesis_completed().await },
  )
  .await
}

/// The time of the latest finalized block, asked until the node answers.
#[expect(closure_returning_async_block)]
async fn latest_time(serai: &Serai) -> Duration {
  ask("the latest finalized block's time", move || async move {
    let latest = serai.latest_finalized_block_number().await.map_err(|e| format!("{e:?}"))?;
    let block = serai
      .block_by_number(latest)
      .await
      .map_err(|e| format!("{e:?}"))?
      .ok_or_else(|| format!("no block {latest}"))?;
    Ok::<_, String>(Duration::from_millis(block.header.unix_time_in_millis()))
  })
  .await
}

/// Publish the opening until a finalized block includes it, or genesis has completed.
///
/// A refusal or a slow block is logged and published again, as an unsigned transaction stays valid
/// until a block includes it. Genesis completing, by this or by a copy published by hand, ends it.
async fn publish_tx(serai: &Serai, tx: &Transaction) {
  loop {
    if genesis_completed(serai).await {
      return;
    }
    if let Err(e) = serai.publish_transaction(tx).await {
      println!("Serai's node didn't take the transaction ({e:?}); looking again for 60s");
    }
    for _ in 0 .. 60 {
      tokio::time::sleep(Duration::from_secs(1)).await;
      let Ok(latest) = serai.latest_finalized_block_number().await else { continue };
      let Ok(Some(block)) = serai.block_by_number(latest).await else { continue };
      if block.transactions.iter().any(|transaction| transaction == tx) {
        return;
      }
    }
    println!("The transaction wasn't in a finalized block within 60 seconds; publishing it again");
  }
}

fn musig_sign(set: ValidatorSet, pairs: &[Pair], msg: &[u8]) -> RistrettoSignature {
  let mut pub_keys = vec![];
  for pair in pairs {
    let public_key = <Ristretto as GroupIo>::read_G(&pair.public().0[..]).unwrap();
    pub_keys.push(public_key);
  }

  let mut musig_keys = HashMap::new();
  for i in 0 .. pairs.len() {
    let secret_key =
      <Ristretto as GroupIo>::read_F(&pairs[i].as_ref().secret.to_bytes()[.. 32]).unwrap();
    assert_eq!(Ristretto::generator() * secret_key, pub_keys[i]);

    let keys =
      musig::<Ristretto>(set.musig_context(), Zeroizing::new(secret_key), &pub_keys).unwrap();
    assert_eq!(
      sp_core::sr25519::Public::from(keys.group_key().to_bytes()),
      set
        .musig_key(&pub_keys.iter().map(|pub_key| pub_key.to_bytes().into()).collect::<Vec<_>>())
        .unwrap()
    );
    musig_keys.insert(keys.params().i(), keys);
  }

  // Map from the `Ristretto` ciphersuite used for MuSig to the `Ristretto` ciphersuite used for
  // signing, the former preferring Blake2b and the latter derived from FROST's IRTF standard
  let musig_keys = musig_keys
    .into_iter()
    .map(|(i, keys)| {
      (
        i,
        ThresholdKeys::<frost::curve::Ristretto>::new(
          keys.params(),
          keys.interpolation().clone(),
          keys.original_secret_share().clone(),
          (1 ..= keys.params().n())
            .map(|i| {
              let i = Participant::new(i).unwrap();
              (i, keys.original_verification_share(i))
            })
            .collect::<HashMap<_, _>>(),
        )
        .unwrap(),
      )
    })
    .collect::<HashMap<_, _>>();

  let machines =
    frost::tests::algorithm_machines(&mut OsRng, &Schnorrkel::new(b"substrate"), &musig_keys);
  let sig = frost::tests::sign_without_caching(&mut OsRng, machines, msg);
  assert!(
    sp_core::sr25519::Public::from(musig_keys.values().next().unwrap().group_key().to_bytes())
      .verify(&msg, &sig.to_bytes().into())
  );

  sig.into()
}

/// Oraclize the genesis values, ending the genesis period and initializing the pools.
async fn oraclize_values(serai: &Serai) {
  let values =
    GenesisValues { ether: Amount(3_097_630), dai: Amount(1417), monero: Amount(488_472) };
  let set = ValidatorSet { network: NetworkId::Serai, session: Session(0) };
  let pairs = dev_pairs_in_genesis_order();

  let signature = musig_sign(set, &pairs, &values.oraclize_values_message());
  let mut signature_participants = bitvec::vec::BitVec::new();
  for _ in 0 .. pairs.len() {
    signature_participants.push(true);
  }

  publish_tx(
    serai,
    &Transaction::Unsigned {
      call: Call::GenesisLiquidity(GenesisLiquidityCall::oraclize_values {
        values,
        signature_participants: signature_participants.try_into().unwrap(),
        signature,
      })
      .try_into()
      .unwrap(),
    },
  )
  .await;
}

/// Complete the genesis liquidity period.
///
/// This waits for real genesis liquidity deposits on every external network, and then oraclizes
/// the genesis values (initializing the pools). Every question to Serai's node is retried until
/// answered, and genesis completion is checked again just before publishing the opening
/// (specification 32).
#[expect(closure_returning_async_block)]
pub(crate) async fn complete_genesis(serai: &Serai) {
  if genesis_completed(serai).await {
    println!("Genesis already completed.");
    return;
  }

  println!(
    "Waiting for BTC, ETH, DAI and XMR genesis liquidity deposits before oraclizing values..."
  );
  loop {
    let mut all_deposited = true;
    for coin in
      [ExternalCoin::Bitcoin, ExternalCoin::Ether, ExternalCoin::Dai, ExternalCoin::Monero]
    {
      let supply = ask("a coin's genesis liquidity", move || async move {
        serai.state().await?.genesis_liquidity_supply(coin).await
      })
      .await;
      if supply.0 == 0 {
        all_deposited = false;
      }
    }
    if all_deposited {
      break;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
  }

  // wait for genesis time to complete
  {
    const GENESIS_LIQUIDITY_TIME: Duration = Duration::from_hours(5);

    let genesis_time = ask("block 1's time", move || async move {
      let block = serai
        .block_by_number(1)
        .await
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "no block 1 yet".to_owned())?;
      Ok::<_, String>(Duration::from_millis(block.header.unix_time_in_millis()))
    })
    .await;
    let end_of_genesis = genesis_time.saturating_add(GENESIS_LIQUIDITY_TIME);

    let remaining = end_of_genesis.saturating_sub(latest_time(serai).await);
    if !remaining.is_zero() {
      println!("Waiting {}s for the genesis liquidity period to pass...", remaining.as_secs());
    }
    while latest_time(serai).await < end_of_genesis {
      tokio::time::sleep(Duration::from_secs(30)).await;
    }
  }

  // Someone may have published the opening by hand meanwhile: Serai would refuse a second as stale
  if genesis_completed(serai).await {
    println!("Genesis already completed.");
    return;
  }

  println!("Oraclizing genesis values...");
  oraclize_values(serai).await;

  // `oraclize_values`' dispatch may fail even when its `validate_unsigned` passes, so confirm
  // genesis actually completed. Where it doesn't, the network stays up for someone to read why.
  let mut waited = 0u64;
  loop {
    if genesis_completed(serai).await {
      println!("Genesis completed. Pools are initialized.");
      return;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    waited += 3;
    if waited.is_multiple_of(30) {
      println!(
        "`oraclize_values` was published {waited}s ago, yet genesis hasn't completed. Read Serai's \
         events for the call's error. Still waiting."
      );
    }
  }
}

/// The genesis step by hand, for a network whose harness stopped and left its containers running
/// (specification 32): run against the running network's first node (`SERAI_RPC_URL`, or
/// `http://127.0.0.1:9944`), starting no containers. Ignored, so the crate's tests never reach a
/// live node: `cargo test -p serai-full-stack-tests publish_opening -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "hand tool: connects to a running Serai node"]
async fn publish_opening() {
  #[expect(clippy::disallowed_methods)]
  let url = std::env::var("SERAI_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:9944".to_owned());
  let serai = Serai::new(url).expect("couldn't make a client of Serai's node");
  complete_genesis(&serai).await;
}
