# seed15

seed15 is a standard for converting user secrets into seed phrases. The seed15
library includes helper functions for generating new seeds (which contain 16
bytes of entropy) and converting between seeds and seed phrases.

The seed15 seed phrase uses a 1024 word english dictionary, meaning each word
contains 10 bits of entropy. 13 words total are needed to get the 128 bits that
map to a 16 byte seed. The final two bits of the 13th word are explicitly set
to zero, a valid seed may only use a specific 256 words of the dictionary for
the 13th word.

The final two words are used for a checksum. The checksum is computed by taking
the sha256 of the seed and then using the first 20 bits of the result. 20 bits
of entropy means that an incorrectly transcribed seed has a one in a million
chance of having a correct checksum. Using a 20 bit checksum also means that
with high probability the correct seed can be found by brute force without any
false positives as long as only one or two words is incorrect.

A full specification of the seed protocol can be found here:
https://blog.sia.tech/a-technical-breakdown-of-mysky-seeds-ba9964505978
