#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! seed-manager is a crate with a number of helper functions for working with cryptographic seeds,
//! including moving between seeds and seed phrases.
//!
//! ```
//! use seed15::random_seed;
//! use seed15::phrase::{seed_to_seed_phrase, seed_phrase_to_seed};
//! use seed15::keypair::keypair_from_seed;
//!
//! // Create a seed, convert it to a human-readable phrase, then convert the phrase back to a
//! // seed.
//! let new_seed = random_seed();
//! let phrase = seed_to_seed_phrase(new_seed);
//! let seed = seed_phrase_to_seed(&phrase).unwrap();
//!
//! // Use the seed to create an ed25519 keypair.
//! let keypair = keypair_from_seed(seed);
//! ```

pub mod dictionary;
pub mod keypair;
pub mod phrase;

use userspace_rng::random256;

/// Seed defines the type for a kardashev seed. The seed itself is not intended to be
/// human-friendly and therefore has no checksum.
pub type Seed = [u8; 16];

/// random_seed will generate a new random seed using secure userspace entropy from the
/// userspace-random crate.
pub fn random_seed() -> Seed {
    let mut seed: Seed = [0u8; 16];
    let rand_bytes = random256();
    seed.copy_from_slice(&rand_bytes[..16]);
    seed
}
