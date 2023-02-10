#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! seed implements functions for moving between a seed and a seed phrase. This blog post provides
//! a full specification for the code presented here:
//!
//! <https://blog.sia.tech/a-technical-breakdown-of-mysky-seeds-ba9964505978>

use crate::Seed;
use anyhow::{bail, Error, Result};
use dictionary_1024::{index_of_word, word_at_index, words_match};
use sha2::{Digest, Sha256};


/// SEED_ENTROPY_WORDS describes the number of words in a seed phrase that contribute to its
/// fundamental entropy. These are the first 13 words.
pub const SEED_ENTROPY_WORDS: usize = 13;

/// SEED_CHECKSUMWORDS describes the number of words in a seed phrase that contribute to the
/// checksum. The checksum is used to ensure copying errors did not occur if a human is
/// transcribing a seed manually. There is enough entropy in the checksum that an error can usually
/// be corrected by brute-force with zero false positives.
pub const SEED_CHECKSUM_WORDS: usize = 2;

/// seed_to_seed_phrase will convert a seed into a seed phrase.
pub fn seed_to_seed_phrase(seed: Seed) -> String {
    // Add the entropy words. We process the seed one bit at a time.
    let mut phrase: String = "".to_string();
    let mut current_byte = 0;
    let mut current_bit = 0;
    for i in 0..SEED_ENTROPY_WORDS {
        // All words have 10 bits except the final word, which has 8 bits.
        let mut bits = 10;
        if i == SEED_ENTROPY_WORDS - 1 {
            bits = 8;
        }

        // Iterate over each bit in the next word.
        let mut word_index: usize = 0;
        for j in 0..bits {
            // set the bit in the word_index if it is set in the seed.
            let bit_is_set = (seed[current_byte] & (1 << (8 - current_bit - 1))) > 0;
            if bit_is_set {
                word_index |= 1 << (bits - j - 1);
            }

            // move on to the next bit.
            current_bit += 1;
            if current_bit == 8 {
                current_bit = 0;
                current_byte += 1;
            }
        }

        // Look up the word and add it to the phrase.
        if i != 0 {
            phrase += " ";
        }
        phrase += &word_at_index(word_index);
    }

    // Add the checksum words.
    let checksum_words = seed_to_checksum_words(seed);
    phrase += " ";
    phrase += &checksum_words[0];
    phrase += " ";
    phrase += &checksum_words[1];
    phrase
}

/// seed_phrase_to_seed converts a seed phrase to a Uint8Array
pub fn seed_phrase_to_seed(phrase: &str) -> Result<Seed, Error> {
    // Break the phrase into its component words
    let all_words: Vec<&str> = phrase.split(' ').collect();
    let expected_words = SEED_ENTROPY_WORDS + SEED_CHECKSUM_WORDS;
    if all_words.len() != expected_words {
        bail!(
            "expecting {} words but got {} words",
            expected_words,
            all_words.len()
        );
    }

    // Build the seed from the entropy words. We build the seed out one bit at a time. We convert
    // the word into a set of entropy bits, then iterate over the bits and add them to the seed.
    let mut seed: Seed = [0u8; 16];
    let mut current_byte = 0;
    let mut current_bit = 0;
    for i in 0..SEED_ENTROPY_WORDS {
        let word_index = index_of_word(all_words[i])?;

        // Pack the bits into the seed.
        let mut bits = 10;
        if i == SEED_ENTROPY_WORDS - 1 {
            bits = 8;
            if word_index > 255 {
                bail!(
                    "seed phrase is not valid: {} cannot be the 13th word prefix",
                    &all_words[SEED_ENTROPY_WORDS - 1]
                );
            }
        }
        for j in 0..bits {
            // Set the current bit if needed.
            let bit_is_set = (word_index & (1 << (bits - j - 1))) > 0;
            if bit_is_set {
                seed[current_byte] |= 1 << (8 - current_bit - 1);
            }

            // Move on to the next bit.
            current_bit += 1;
            if current_bit == 8 {
                current_bit = 0;
                current_byte += 1;
            }
        }
    }

    // Verify the checksum on the seed.
    let checksum_words = seed_to_checksum_words(seed);
    if !words_match(&checksum_words[0], all_words[SEED_ENTROPY_WORDS]) {
        bail!(
            "first checksum word is incorrect, expecting prefix {} but got {}",
            checksum_words[0],
            all_words[SEED_ENTROPY_WORDS]
        );
    }
    if !words_match(&checksum_words[1], all_words[SEED_ENTROPY_WORDS + 1]) {
        bail!(
            "second checksum word is incorrect, expecting prefix {} but got {}",
            checksum_words[1],
            all_words[SEED_ENTROPY_WORDS + 1]
        );
    }

    // Success.
    Ok(seed)
}

/// seed_to_checksum_words will provide the checksum words for a given seed.
fn seed_to_checksum_words(seed: Seed) -> [String; SEED_CHECKSUM_WORDS] {
    // Hash the seed to get the checksum entropy.
    let mut hasher = Sha256::new();
    hasher.update(&seed);
    let r = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&r);

    // Convert the first 20 bits of the entropy into two words.
    let mut word1: usize = (result[0] as usize) << 8;
    word1 += result[1] as usize;
    word1 >>= 6;
    let mut word2: usize = (result[1] as usize) << 10;
    word2 &= 0xffff;
    word2 += (result[2] as usize) << 2;
    word2 >>= 6;
    [word_at_index(word1), word_at_index(word2)]
}

/// valid_seed_phrase will return an error if the seed phrase is not valid.
pub fn valid_seed_phrase(phrase: &str) -> Result<(), Error> {
    match seed_phrase_to_seed(phrase) {
        Ok(_) => Ok(()),
        Err(e) => bail!("seed phrase invalid: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_seed;

    // verify_conversion will convert a given seed into a phrase and then back into a seed,
    // confirming that the new seed has its original value.
    fn verify_conversion(seed: Seed) {
        let phrase = seed_to_seed_phrase(seed);
        println!("{}", phrase);
        valid_seed_phrase(&phrase).unwrap();
        let seed_conf = match seed_phrase_to_seed(&phrase) {
            Ok(s) => s,
            Err(e) => panic!("verify_conversion failed: {}\n\t{:?}", e, seed),
        };
        if seed != seed_conf {
            panic!(
                "seed conversion failed: \n\t{:?}\n\t{:?}\n\t{}",
                seed, seed_conf, phrase
            );
        }
    }

    #[test]
    // Verify that each of these bad seeds results in an error.
    fn check_unhappy_seeds() {
        let good_seed = random_seed();
        let good_phrase = seed_to_seed_phrase(good_seed);

        // Explore a bad checksum.
        let mut phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        let wai0 = word_at_index(0);
        let wai1 = word_at_index(1);
        let wai2 = word_at_index(2);
        phrase_words[0] = &wai0;
        phrase_words[1] = &wai1;
        phrase_words[2] = &wai2;
        let bad_phrase = phrase_words.join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();

        // Explore a malformed word.
        let mut phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        phrase_words[0] = "ab";
        let bad_phrase = phrase_words.join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();

        // Explore just a bad checksum.
        let mut phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        if phrase_words[14] == word_at_index(0) {
            phrase_words[14] = &wai1;
        } else {
            phrase_words[14] = &wai0;
        }
        let bad_phrase = phrase_words.join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();

        // Explore a missing word.
        let mut phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        phrase_words[0] = "abx";
        let bad_phrase = phrase_words.join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();

        // Explore adding an extra word.
        let mut phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        phrase_words.push(&wai0);
        let bad_phrase = phrase_words.join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();

        // Explore removing a word.
        let phrase_words: Vec<&str> = good_phrase.split(" ").collect();
        let bad_phrase = phrase_words[..14].join(" ");
        valid_seed_phrase(&bad_phrase).unwrap_err();
    }

    #[test]
    // perform a basic test to see that a seed can be generated, converted into a seed phrase, and
    // then converted back.
    fn check_seed_phrases() {
        // Try performing some generic seed phrase conversions.
        let mut seed = [0u8; 16];
        verify_conversion(seed);
        seed[0] = 185;
        verify_conversion(seed);
        seed[1] = 46;
        verify_conversion(seed);
        seed[2] = 7;
        verify_conversion(seed);
        seed[3] = 1;
        verify_conversion(seed);
        seed[4] = 254;
        verify_conversion(seed);
        seed[5] = 2;
        verify_conversion(seed);

        // Try with 1000 random seeds.
        for _ in 0..1000 {
            let seed = random_seed();
            verify_conversion(seed);
        }

        // Test a seed where the final entropy word is using a strategically chosen value such that
        // it is incorrect, but the first 8 bits are still valid and will pass the checksum if the
        // bounds check is not deliberate. Run the test 1000 times.
        for _ in 0..1000 {
            let seed = random_seed();
            let phrase = seed_to_seed_phrase(seed);
            let mut words: Vec<&str> = phrase.split(" ").collect();

            // Find the index of the 13th word.
            let word_index = index_of_word(words[12]).unwrap();
            if word_index > 255 {
                panic!("seed generated randomly with 13th word out of bounds");
            }
            // Add the extra bit and check for a valid seed.
            let wai = word_at_index(word_index + 256);
            words[12] = &wai;
            let mut altered_phrase = words[0].to_string();
            for i in 1..words.len() {
                altered_phrase += " ";
                altered_phrase += words[i];
            }
            match valid_seed_phrase(&altered_phrase) {
                Ok(()) => panic!("phrase should not be valid after manipulation"),
                Err(_) => {}
            };
        }
    }
}
