use core::fmt;
use std::collections::HashMap;

use ciphersuite::*;
use ciphersuite_kp256::Secp256k1;

use bitcoin_serai::bitcoin::{
  hashes::Hash as _,
  block::{Header, Block as BBlock},
};

use serai_client_bitcoin::Address;

use serai_db::Db;
use primitives::{ReceivedOutput, EventualityTracker};

use crate::{hash_bytes, scan::scanner, output::Output, transaction::Eventuality};

#[derive(Clone, Debug)]
pub(crate) struct BlockHeader(pub(crate) Header);
impl primitives::BlockHeader for BlockHeader {
  fn id(&self) -> [u8; 32] {
    hash_bytes(self.0.block_hash().to_raw_hash())
  }
  fn parent(&self) -> [u8; 32] {
    hash_bytes(self.0.prev_blockhash.to_raw_hash())
  }
}

#[derive(Clone)]
pub(crate) struct Block<D: 'static + Send + Sync + Clone>(pub(crate) D, pub(crate) BBlock);
impl<D: 'static + Send + Sync + Clone> fmt::Debug for Block<D> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("Block").field("1", &self.1).finish_non_exhaustive()
  }
}

impl<D: 'static + Send + Sync + Db> primitives::Block for Block<D> {
  type Header = BlockHeader;

  type Key = <Secp256k1 as WrappedGroup>::G;
  type Address = Address;
  type Output = Output;
  type Eventuality = Eventuality;

  fn id(&self) -> [u8; 32] {
    primitives::BlockHeader::id(&BlockHeader(self.1.header))
  }

  fn scan_for_outputs_unordered(
    &self,
    _latest_active_key: Self::Key,
    key: Self::Key,
  ) -> Vec<Self::Output> {
    let scanner = scanner(key);

    let mut res = vec![];
    // We skip the coinbase transaction as its burdened by maturity
    for tx in &self.1.txdata[1 ..] {
      for output in scanner.scan_transaction(tx) {
        res.push(Output::new(&self.0, tx, output, key));
      }
    }
    res
  }

  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    let mut res = HashMap::new();
    for tx in &self.1.txdata[1 ..] {
      /*
        The ID in the byte order `Eventuality::lookup` uses: `bitcoin_serai`'s
        `SignableTransaction::txid`, and `Output::transaction_id`, are the txid's bytes as they are,
        not reversed (as `hash_bytes` reverses them).
      */
      let id = tx.compute_txid().to_raw_hash().to_byte_array();
      if let Some(eventuality) = eventualities.active_eventualities.remove(id.as_slice()) {
        res.insert(id, eventuality);
      }
    }
    res
  }
}

#[cfg(test)]
mod tests {
  use bitcoin_serai::bitcoin::{
    Amount, Network, TxOut, ScriptBuf,
    absolute::LockTime,
    blockdata::constants::genesis_block,
    transaction::{Version, Transaction},
  };

  use serai_db::MemDb;

  use primitives::{Block as _, Eventuality as _};

  use super::*;

  #[test]
  fn an_eventuality_resolves_in_the_block_with_its_transaction() {
    let tx = Transaction {
      version: Version(2),
      lock_time: LockTime::ZERO,
      input: vec![],
      output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
    };
    // The Eventuality for it, as the planner makes it (`SignableTransaction::txid`)
    let eventuality = Eventuality {
      txid: tx.compute_txid().to_raw_hash().to_byte_array(),
      singular_spent_output: None,
    };

    let mut block = genesis_block(Network::Regtest);
    block.txdata.push(tx);
    let block = Block(MemDb::new(), block);

    let mut tracker = EventualityTracker::default();
    tracker.active_eventualities.insert(eventuality.lookup(), eventuality.clone());
    let resolved = block.check_for_eventuality_resolutions(&mut tracker);
    assert!(tracker.active_eventualities.is_empty());
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved.values().next().unwrap().id(), eventuality.id());
  }
}
