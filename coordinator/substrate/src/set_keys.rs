use core::future::Future;
use std::sync::Arc;

use serai_db::{Transaction as _, Db};

use serai_client_serai::{
  abi::primitives::{
    network_id::ExternalNetworkId,
    validator_sets::{Session, ExternalValidatorSet},
  },
  Serai,
};

use serai_task::ContinuallyRan;

use crate::Keys;

/// Which session a set of keys are for, relative to Serai's current session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeysFor {
  RetiredSession,
  CurrentOrNextSession,
  SessionYetToStart,
}

/*
  Serai's `set_keys` is for its latest decided session, which is at most one session ahead of the
  current session: while session `n` is current, session `n + 1` is decided and sets its keys, and
  only then is it handed over to. An external network's first session is a case of this, as it has
  no current session until its keys are set (`set_keys` calls `accept_handover` for `Session(0)`).
*/
fn keys_for(session: Session, current_session: Option<Session>) -> KeysFor {
  let next_session = current_session.map_or(0, |current| current.0 + 1);
  if current_session.is_some_and(|current| session.0 < current.0) {
    KeysFor::RetiredSession
  } else if session.0 <= next_session {
    KeysFor::CurrentOrNextSession
  } else {
    KeysFor::SessionYetToStart
  }
}

/// Set keys from `Keys` on Serai.
pub struct SetKeysTask<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>> {
  db: D,
  serai: Arc<Serai>,
}

impl<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>> SetKeysTask<D> {
  /// Create a task to publish slash reports onto Serai.
  pub fn new(db: D, serai: Arc<Serai>) -> Self {
    Self { db, serai }
  }
}

impl<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>> ContinuallyRan
  for SetKeysTask<D>
{
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      for network in ExternalNetworkId::all() {
        let mut txn = self.db.txn();
        let Some((session, keys)) = Keys::take(&mut txn, network) else {
          // No keys to set
          continue;
        };

        // This uses the latest finalized block, not the latest cosigned block, which should be
        // fine as in the worst case, the only impact is no longer attempting TX publication
        let serai = self.serai.state().await.map_err(|e| format!("{e:?}"))?;
        let current_session =
          serai.current_session(network.into()).await.map_err(|e| format!("{e:?}"))?;
        match keys_for(session, current_session) {
          // Only attempt to set these keys if this isn't a retired session
          KeysFor::RetiredSession => {
            // Commit the txn to take these keys from the database and not try it again later
            txn.commit();
            continue;
          }
          KeysFor::CurrentOrNextSession => {}
          // This would mean the Serai node is resyncing and is behind where it prior was
          KeysFor::SessionYetToStart => {
            Err("have a keys for a session Serai has yet to start".to_owned())?;
          }
        }

        // If this session already has had its keys set, move on
        if serai
          .keys(ExternalValidatorSet { network, session })
          .await
          .map_err(|e| format!("{e:?}"))?
          .is_some()
        {
          txn.commit();
          continue;
        }

        match self.serai.publish_transaction(&keys).await {
          Ok(()) => {
            txn.commit();
            made_progress = true;
          }
          // This could be specific to this TX (such as an already in mempool error) and it may be
          // worthwhile to continue iteration with the other pending slash reports. We assume this
          // error ephemeral and that the latency incurred for this ephemeral error to resolve is
          // miniscule compared to the window reasonable to set the keys. That makes this a
          // non-issue.
          Err(e) => Err(format!("couldn't publish set keys transaction: {e:?}"))?,
        }
      }
      Ok(made_progress)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn keys_for_sessions() {
    // An external network's first keys are set while it has no current session
    assert_eq!(keys_for(Session(0), None), KeysFor::CurrentOrNextSession);
    assert_eq!(keys_for(Session(1), None), KeysFor::SessionYetToStart);

    // While session 3 is current, its keys and session 4's may be set
    assert_eq!(keys_for(Session(2), Some(Session(3))), KeysFor::RetiredSession);
    assert_eq!(keys_for(Session(3), Some(Session(3))), KeysFor::CurrentOrNextSession);
    assert_eq!(keys_for(Session(4), Some(Session(3))), KeysFor::CurrentOrNextSession);
    assert_eq!(keys_for(Session(5), Some(Session(3))), KeysFor::SessionYetToStart);
  }
}
