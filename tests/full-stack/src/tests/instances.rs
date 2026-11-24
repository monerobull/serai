use std::collections::HashMap;

use rand_core::OsRng;

use ciphersuite::{
  group::{ff::PrimeField as _, GroupEncoding as _},
  WrappedGroup, WithPreferredHash,
};
use dalek_ff_group::Ristretto;
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

use sp_core::{Pair as _, sr25519::Pair};

use dockertest::{
  LogAction, LogPolicy, LogSource, LogOptions, StartPolicy, TestBodySpecification, PullPolicy,
  Image,
};

use serai_client_serai::abi::primitives::network_id::ExternalNetworkId;

use crate::{RPC_USER, RPC_PASS};

// This is for test only.
fn insecure_arbitrary_key_from_name<C: WithPreferredHash>(name: &str) -> C::F {
  C::hash_to_F([b"insecure arbitrary key".as_slice(), name.as_bytes()].concat())
}

fn insecure_keypair_from_name(name: &str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

/// What a service reads from its environment, which it receives from a Secret Store
/// (`secret-store/README.md`): each name as the service reads it, with its value.
pub type Variables = Vec<(String, String)>;

/// The names a Secret Store sends `service` under: `{SERVICE}_{NAME}`, set on the Secret Store.
pub fn for_service(service: &str, variables: Variables) -> Variables {
  variables.into_iter().map(|(name, value)| (format!("{service}_{name}"), value)).collect()
}

/// A Secret Store, with every variable it's to send set on it as `{SERVICE}_{NAME}`, and the
/// hosts of the services it serves set as `{SERVICE}` by whoever starts it. Each service waits
/// for it on port 59119 and takes the last value sent of each name, so these are what it reads
/// (testing only: the entropy it's started with goes unused, see its image).
pub fn secret_store_instance(variables: Variables) -> TestBodySpecification {
  serai_docker_tests::build("secret-store".to_owned());

  TestBodySpecification::with_image(
    Image::with_repository("serai-dev-secret-store").pull_policy(PullPolicy::Never),
  )
  .replace_env(variables.into_iter().collect())
}

/// The coordinator, and what its Secret Store sends it but its hosts (`SERAI_HOSTNAME`,
/// `MESSAGE_QUEUE_RPC`), which are known once the network's up.
pub fn coordinator_instance(
  name: &str,
  message_queue_key: <Ristretto as WrappedGroup>::F,
) -> (TestBodySpecification, Variables) {
  serai_docker_tests::build("coordinator".to_owned());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-coordinator").pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [(
      "RUST_LOG".to_owned(),
      // Testing only: `info` for every target the rest don't name, as env_logger logs nothing for
      // a target no directive names. Without it, a task's error (`serai_task`) and the cosigning's
      // lines were dropped, and a coordinator that never began a key generation said nothing.
      // `serai_coordinator` names the `serai_coordinator_*` crates too, the libp2p one among them.
      "info,".to_owned() +
        "serai_coordinator=trace," +
        "serai_cosign=debug," +
        "serai_task=debug," +
        "tributary_chain=trace," +
        "tendermint=trace",
    )]
    .into(),
  );
  let variables = vec![
    ("MESSAGE_QUEUE_KEY".to_owned(), hex::encode(message_queue_key.to_repr())),
    ("DB_PATH".to_owned(), "./coordinator-db".to_owned()),
    // genesis's Serai key for this validator (`chain_spec.rs`), which its dev-seeded node holds
    ("SERAI_AUXILIARY_KEY".to_owned(), {
      hex::encode(&insecure_keypair_from_name(name).as_ref().secret.to_bytes()[.. 32])
    }),
  ];
  (composition, variables)
}

/// The host port the first validator's Serai RPC is published on. Each further validator's is
/// published on the port after the prior's.
pub const SERAI_RPC_PORT: u32 = 9944;

pub fn serai_composition(name: &str, index: u32, test_account: &str) -> TestBodySpecification {
  serai_docker_tests::build("serai".to_owned());
  let mut composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-serai").pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [
      ("SERAI_NAME".to_owned(), name.to_lowercase()),
      ("KEY".to_owned(), " ".to_owned()),
      ("SERAI_TEST_ACCOUNT".to_owned(), test_account.to_owned()),
    ]
    .into(),
  );
  // Publish the RPC on a fixed host port so it's reachable at a stable address across launches
  composition.modify_port_map(SERAI_RPC_PORT, SERAI_RPC_PORT + index);
  composition
}

#[expect(dead_code)]
#[derive(Clone)]
pub struct EvrfPublicKeys {
  substrate: [u8; 32],
  network: Vec<u8>,
}

/// A processor, its relayer for Ethereum, and what their Secret Stores send them but their hosts
/// (`MESSAGE_QUEUE_RPC`, `NETWORK_RPC_HOSTNAME`, the relayer's), which are container names.
pub fn processor_instance(
  name: &str,
  network: ExternalNetworkId,
  port: u32,
  message_queue_key: <Ristretto as WrappedGroup>::F,
) -> (Vec<TestBodySpecification>, Variables, Variables, EvrfPublicKeys) {
  let substrate_evrf_key = insecure_arbitrary_key_from_name::<Embedwards25519>(name);
  let substrate_evrf_pub_key = (Embedwards25519::generator() * substrate_evrf_key).to_bytes();
  let substrate_evrf_key = substrate_evrf_key.to_repr();

  let (network_evrf_key, network_evrf_pub_key) = match network {
    ExternalNetworkId::Bitcoin | ExternalNetworkId::Ethereum => {
      let evrf_key = insecure_arbitrary_key_from_name::<Secq256k1>(name);
      let pub_key = (Secq256k1::generator() * evrf_key).to_bytes().to_vec();
      (evrf_key.to_repr().as_ref().to_vec(), pub_key)
    }
    ExternalNetworkId::Monero => {
      let evrf_key = insecure_arbitrary_key_from_name::<Embedwards25519>(name);
      let pub_key = (Embedwards25519::generator() * evrf_key).to_bytes().to_vec();
      (evrf_key.to_repr().as_ref().to_vec(), pub_key)
    }
  };

  let network_str = match network {
    ExternalNetworkId::Bitcoin => "bitcoin",
    ExternalNetworkId::Ethereum => "ethereum",
    ExternalNetworkId::Monero => "monero",
  };
  let image = format!("{network_str}-processor");
  serai_docker_tests::build(image.clone());

  let mut res = vec![TestBodySpecification::with_image(
    Image::with_repository(format!("serai-dev-{image}")).pull_policy(PullPolicy::Never),
  )
  .replace_env(
    [(
      "RUST_LOG".to_owned(),
      "info,serai_processor=trace,serai_processor_key_gen=trace,messages=trace".to_owned(),
    )]
    .into(),
  )];
  // the processor's keys are genesis's for this validator (`chain_spec.rs`), from its name
  let variables = vec![
    ("MESSAGE_QUEUE_KEY".to_owned(), hex::encode(message_queue_key.to_repr())),
    ("SUBSTRATE_AUXILIARY_KEY".to_owned(), hex::encode(substrate_evrf_key)),
    ("NETWORK_AUXILIARY_KEY".to_owned(), hex::encode(network_evrf_key)),
    ("NETWORK_RPC_LOGIN".to_owned(), format!("{RPC_USER}:{RPC_PASS}")),
    ("NETWORK_RPC_PORT".to_owned(), port.to_string()),
    ("DB_PATH".to_owned(), "./processor-db".to_owned()),
  ];
  let mut relayer_variables = vec![];

  if network == ExternalNetworkId::Ethereum {
    serai_docker_tests::build("ethereum-relayer".to_owned());
    res.push(
      TestBodySpecification::with_image(
        Image::with_repository("serai-dev-ethereum-relayer".to_owned())
          .pull_policy(PullPolicy::Never),
      )
      .replace_env(
        // Testing only: `info` for every target the other doesn't name, as the coordinator's
        [("RUST_LOG".to_owned(), "info,serai_ethereum_relayer=trace".to_owned())].into(),
      )
      .set_publish_all_ports(true),
    );
    relayer_variables.push(("DB_PATH".to_owned(), "./ethereum-relayer-db".to_owned()));
  }

  (
    res,
    variables,
    relayer_variables,
    EvrfPublicKeys { substrate: substrate_evrf_pub_key, network: network_evrf_pub_key },
  )
}

const BTC_PORT: u32 = 8332;
const BTC_P2P_PORT: u32 = 8333;
const ETH_PORT: u32 = 8545;
const XMR_PORT: u32 = 18081;
const XMR_P2P_PORT: u32 = 18080;
// The Monero node's ports are published on the host as a secondary node's, as the host may run a
// primary Monero node on the usual ones
const XMR_HOST_PORT: u32 = 28081;
const XMR_HOST_P2P_PORT: u32 = 28080;

/*
  Every node publishes its RPC (and P2P, where it's peered with) on a fixed host port so it's
  reachable at a stable address across launches, instead of the random port Docker would assign.
*/
pub fn network_instance(network: ExternalNetworkId) -> (TestBodySpecification, u32) {
  pub fn bitcoin_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("bitcoin".to_owned());

    let mut composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
    );
    composition.modify_port_map(BTC_PORT, BTC_PORT);
    composition.modify_port_map(BTC_P2P_PORT, BTC_P2P_PORT);

    (composition, BTC_PORT)
  }

  pub fn ethereum_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("ethereum".to_owned());

    let mut composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-ethereum").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict);
    composition.modify_port_map(ETH_PORT, ETH_PORT);
    (composition, ETH_PORT)
  }

  pub fn monero_instance() -> (TestBodySpecification, u32) {
    serai_docker_tests::build("monero".to_owned());

    let mut composition = TestBodySpecification::with_image(
      Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
    )
    .set_start_policy(StartPolicy::Strict);
    composition.modify_port_map(XMR_PORT, XMR_HOST_PORT);
    composition.modify_port_map(XMR_P2P_PORT, XMR_HOST_P2P_PORT);
    (composition, XMR_PORT)
  }
  match network {
    ExternalNetworkId::Bitcoin => bitcoin_instance(),
    ExternalNetworkId::Ethereum => ethereum_instance(),
    ExternalNetworkId::Monero => monero_instance(),
  }
}

type MessageQueuePrivateKey = <Ristretto as WrappedGroup>::F;
/// The message queue, the keys of the services it serves, and what its Secret Store sends it.
pub fn message_queue_instance() -> (
  MessageQueuePrivateKey,
  HashMap<ExternalNetworkId, MessageQueuePrivateKey>,
  TestBodySpecification,
  Variables,
) {
  serai_docker_tests::build("message-queue".to_owned());

  let coord_key = <Ristretto as WrappedGroup>::F::random(&mut OsRng);
  let priv_keys = ExternalNetworkId::all()
    .map(|n| (n, <Ristretto as WrappedGroup>::F::random(&mut OsRng)))
    .collect::<HashMap<_, _>>();

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-message-queue").pull_policy(PullPolicy::Never),
  )
  .set_log_options(Some(LogOptions {
    action: LogAction::Forward,
    policy: LogPolicy::Always,
    source: LogSource::Both,
  }))
  // Testing only: `info` for every target the other doesn't name, as the coordinator's
  .replace_env([("RUST_LOG".to_owned(), "info,serai_message_queue=trace".to_owned())].into())
  .set_publish_all_ports(true);
  let variables = vec![
    ("COORDINATOR_KEY".to_owned(), hex::encode((Ristretto::generator() * coord_key).to_bytes())),
    (
      "BITCOIN_KEY".to_owned(),
      hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Bitcoin]).to_bytes()),
    ),
    (
      "ETHEREUM_KEY".to_owned(),
      hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Ethereum]).to_bytes()),
    ),
    (
      "MONERO_KEY".to_owned(),
      hex::encode((Ristretto::generator() * priv_keys[&ExternalNetworkId::Monero]).to_bytes()),
    ),
    ("DB_PATH".to_owned(), "./message-queue-db".to_owned()),
  ];

  (coord_key, priv_keys, composition, variables)
}
