#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! keypair contains helper functions for using keypairs derived from seeds.

use ed25519_dalek::Keypair;
use sha2::{Digest, Sha256};

use crate::Seed;

struct SeedCsprng {
    seed: Seed,
    used: bool,
}

impl rand_core::CryptoRng for SeedCsprng {}

// The RngCore implementation is intentionally quite restricted, it's supposed to be used
// exclusively internally to seed the csprng required by Keypair::generate(). As a result, the
// implementation has a lot of panics in it to ensure that people don't wander outside the
// permitted bounds of the SeedCsprng without an abrupt warning.
impl rand_core::RngCore for SeedCsprng {
    fn next_u32(&mut self) -> u32 {
        panic!("cannot use next_u32 with type SeedCsprng");
    }

    fn next_u64(&mut self) -> u64 {
        panic!("cannot use next_u64 with type SeedCsprng");
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.len() != 32 {
            panic!("expected 32 bytes to be used, got: {}", dest.len());
        }
        if self.used {
            panic!("entropy has already been used");
        }
        self.used = true;

        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        let r = hasher.finalize();
        dest.copy_from_slice(&r);
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("cannot use try_fill_bytes with SeedCsprng");
    }
}

/// keypair_from_seed produces an ed25519 keypair from a 16 byte seed.
pub fn keypair_from_seed(seed: Seed) -> Keypair {
    let mut csprng = SeedCsprng { seed, used: false };
    Keypair::generate(&mut csprng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    // some basic testing to make sure keypair_from_seed runs correctly.
    fn check_keypair_from_seed() {
        let seed: Seed = [0u8; 16];
        let keypair = keypair_from_seed(seed);
        let msg = [0u8; 32];
        let sig = keypair.sign(&msg);
        match keypair.public.verify_strict(&msg, &sig) {
            Ok(()) => {}
            Err(e) => panic!("signature verification failed: {}", e),
        }
    }
}
