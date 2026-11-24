#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{ops::Deref as _, str::FromStr as _, fmt::Write as _, time::Duration};
use std::{
  collections::HashMap,
  fs,
  net::{ToSocketAddrs as _, TcpStream},
  thread::sleep,
  env,
};

use zeroize::Zeroizing;

mod hex;

mod derive;

mod encryption;
use encryption::EncryptedSocket;

#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc::wrap(std::alloc::System);

// 5132 ^ (((b'sec'[0] << 14) | (b'sec'[1] << 7) | (b'sec'[2])) % (1 << 16))
const PORT: u16 = 59119;

fn connection_timeout() -> Duration {
  #[expect(clippy::disallowed_methods)]
  let connection_timeout = env::var("CONNECTION_TIMEOUT")
    .map(|timeout| {
      Duration::from_millis(
        u16::from_str(&timeout)
          .expect("`CONNECTION_TIMEOUT` environment variable wasn't a valid `u16`")
          .into(),
      )
    })
    .unwrap_or({
      const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
      DEFAULT_CONNECTION_TIMEOUT
    });
  assert!(!connection_timeout.is_zero(), "connection timeout must not be 0");
  connection_timeout
}

// `ExternalNetworkId` is inlined here to avoid a dependency on `serai-primitives`
fn external_networks() -> impl Iterator<Item = &'static str> {
  ["bitcoin", "ethereum", "monero"].into_iter()
}

fn services() -> impl Iterator<Item = String> {
  external_networks()
    .map(|network| format!("PROCESSOR_{}", network.to_uppercase()))
    .chain(core::iter::once("MESSAGE_QUEUE".to_owned()))
    .chain(core::iter::once("COORDINATOR".to_owned()))
    .chain(core::iter::once("SERAI_NODE".to_owned()))
}

/// Fetch variables for this service via the environment.
fn env_variables(service: &str) -> impl Iterator<Item = (String, String)> {
  let prefix = format!("{service}_");
  #[expect(clippy::disallowed_methods)]
  let vars = env::vars();
  vars.filter_map(move |(key, value)| key.strip_prefix(&prefix).map(|key| (key.to_owned(), value)))
}

fn all_variables<'a>(
  context: &'a [(String, String)],
  secrets: &'a [(String, Zeroizing<String>)],
  service: &'a str,
) -> impl Iterator<Item = (String, Zeroizing<String>)> {
  context
    .iter()
    .cloned()
    .map(|(key, var)| (key, Zeroizing::new(var)))
    .chain(secrets.iter().cloned())
    .chain(env_variables(service).map(|(key, var)| (key, Zeroizing::new(var))))
}

/// Send `service` its environment, or say why it wasn't sent: the reason names the service's
/// host and what failed, never a variable's value.
fn distribute_to_service(
  context: &[(String, String)],
  secrets: &[(String, Zeroizing<String>)],
  service: &str,
) -> Result<(), String> {
  let mut socket = EncryptedSocket::new({
    let hostname = {
      #[expect(clippy::disallowed_methods)]
      let Ok(mut hostname) = env::var(service) else {
        return Err(format!("`{service}` names no host"));
      };
      assert!(!hostname.contains(':'), "`hostname` specification should omit the port");
      write!(&mut hostname, ":{PORT}").unwrap();
      hostname
    };

    let socket_addr = {
      let socket_addr =
        hostname.to_socket_addrs().map_err(|e| format!("`{hostname}` didn't resolve ({e})"))?;
      let mut socket_addr = socket_addr.collect::<Vec<_>>();
      if socket_addr.len() != 1 {
        return Err(format!("`{hostname}` resolved to {} addresses, not one", socket_addr.len()));
      }
      socket_addr.pop().unwrap()
    };

    let connection_timeout = connection_timeout();
    let socket = TcpStream::connect_timeout(&socket_addr, connection_timeout)
      .map_err(|e| format!("couldn't connect to `{hostname}` ({socket_addr}): {e}"))?;
    // Leave Nagle's algorithm enabled
    socket.set_nodelay(false).map_err(|e| format!("couldn't set up `{hostname}`'s socket: {e}"))?;
    // We want blocking sockets
    socket
      .set_nonblocking(false)
      .map_err(|e| format!("couldn't set up `{hostname}`'s socket: {e}"))?;
    socket.set_read_timeout(Some(connection_timeout)).expect("connection timeout is non-zero");
    socket.set_write_timeout(Some(connection_timeout)).expect("connection timeout is non-zero");
    socket
  })
  .map_err(|e| format!("the encrypted handshake with `{service}`'s host failed: {e}"))?;

  let sent = |result: std::io::Result<()>| {
    result.map_err(|e| format!("sending to `{service}`'s host failed partway: {e}"))
  };
  #[expect(clippy::byte_char_slices)]
  {
    for (key, var) in all_variables(context, secrets, service) {
      let mut key = key.into_bytes();
      let mut var = Zeroizing::new(var.deref().clone().into_bytes());
      sent(socket.write_all(&mut [b'"']))?;
      sent(socket.write_all(key.as_mut_slice()))?;
      sent(socket.write_all(&mut [b'"']))?;
      sent(socket.write_all(&mut [b'=']))?;
      sent(socket.write_all(&mut [b'"']))?;
      sent(socket.write_all(var.as_mut_slice()))?;
      sent(socket.write_all(&mut [b'"']))?;
    }
  }
  Ok(())
}

fn main() {
  let (context, secrets) = {
    let entropy = {
      let encoded_entropy = fs::read(&{
        let mut args = env::args().collect::<Vec<_>>();
        assert_eq!(args.len(), 2, "only one argument (the entropy file's path) should be passed");
        args.pop().unwrap()
      })
      .expect("could not open the entropy file");

      let mut entropy = Zeroizing::new([0; 32]);
      hex::decode(&encoded_entropy, entropy.as_mut()).expect("encoded entropy wasn't 64 bytes");
      entropy
    };

    derive::context_and_secrets(entropy)
  };

  for service in services() {
    for (key, var) in all_variables(&context, &secrets[&service], &service) {
      assert!(!key.contains('"'), "environment variable contained '\"' in its key");
      assert!(!var.contains('"'), "environment variable contained '\"' in its value");
    }
  }

  // Print the context to `stdout`
  for (key, var) in &context {
    println!(r#""{key}"="{var}""#);
  }

  // What each service's last round came to, so each outcome is said once, when it changes: a
  // service that can't be reached says why, rather than the store failing silently every minute
  let mut said = HashMap::<String, Result<(), String>>::new();
  loop {
    for service in services() {
      let outcome = distribute_to_service(&context, &secrets[&service], &service);
      if said.get(&service) != Some(&outcome) {
        match &outcome {
          Ok(()) => eprintln!("sent `{service}` its environment"),
          Err(why) => eprintln!("didn't send `{service}` its environment: {why}"),
        }
        said.insert(service, outcome);
      }
    }

    sleep(Duration::from_mins(1));
  }
}
