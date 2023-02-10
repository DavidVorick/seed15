#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! seed15 is a standard for converting user secrets into seed phrases. The seed15
//! library includes helper functions for generating new seeds (which contain 16
//! bytes of entropy) and converting between seeds and seed phrases.
//!
//! The seed15 seed phrase uses a 1024 word english dictionary, meaning each word
//! contains 10 bits of entropy. 13 words total are needed to get the 128 bits that
//! map to a 16 byte seed. The final two bits of the 13th word are explicitly set
//! to zero, a valid seed may only use a specific 256 words of the dictionary for
//! the 13th word.
//!
//! The final two words are used for a checksum. The checksum is computed by taking
//! the sha256 of the seed and then using the first 20 bits of the result. 20 bits
//! of entropy means that an incorrectly transcribed seed has a one in a million
//! chance of having a correct checksum. Using a 20 bit checksum also means that
//! with high probability the correct seed can be found by brute force without any
//! false positives as long as only one or two words is incorrect.
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
//! A full specification of the seed protocol can be found here:
//! https://blog.sia.tech/a-technical-breakdown-of-mysky-seeds-ba9964505978

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
