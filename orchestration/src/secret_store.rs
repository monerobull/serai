use std::path::Path;

use crate::{Network, Os, mimalloc, os, build_serai_service, write_dockerfile};

/// The Secret Store, from which every Serai service but a dev-seeded node receives its
/// environment (`secret-store/README.md`).
///
/// Testing only: this image is for the dev network a FerrySwap test network runs. It makes a fresh
/// entropy file at each start, as the harness hands every service its values as overrides
/// (`{SERVICE}_{NAME}` on this container), so nothing derived from the entropy is used.
pub fn secret_store(orchestration_path: &Path, network: Network) {
  let setup = mimalloc(Os::Alpine, network.release()) +
    &build_serai_service("", Os::Alpine, network.release(), "", "serai-secret-store");

  let run_secret_store = r#"
# Copy the Secret Store binary and relevant license
COPY --from=builder --chown=secretstore /serai/bin/serai-secret-store /bin
COPY --from=builder --chown=secretstore /serai/AGPL-3.0 .

# Run the Secret Store with fresh entropy, 32 bytes as 64 hex characters
CMD ["/bin/sh", "-c", "head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \\n' > /tmp/entropy && exec serai-secret-store /tmp/entropy"]
"#;

  let run = os(Os::Alpine, network.release(), "", "secretstore") + run_secret_store;
  let res = setup + &run;

  let mut secret_store_path = orchestration_path.to_path_buf();
  secret_store_path.push("secret-store");
  secret_store_path.push("Containerfile");

  write_dockerfile(secret_store_path, &res);
}
