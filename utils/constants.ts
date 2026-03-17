/**
 * constants.js
 * Global constants definition module
 * 
 * This file centrally manages all static configuration items to facilitate
 * future adjustments and multi-environment adaptation.
 * All constants are extracted from the original test code configuration to
 * ensure behavioral consistency.
 */

/**
 * @constant {number} KEY_SIZE - Key length for Paillier encryption algorithm (in bits)
 * Used for generating public/private key pairs, affecting encryption strength and performance.
 * Currently set to 1024 bits.
 */
export const KEY_SIZE = 1024;

/**
 * @constant {number} RANDOM_BIT_LENGTH - Bit length for random big integers
 * Used to generate random values required during encryption, ensuring sufficient entropy
 * to enhance security.
 */
export const RANDOM_BIT_LENGTH = 1000;

/**
 * @constant {bigint} RANDOM_RANGE_DIVISOR - Divisor for random number range
 * Used to limit the value range of generated random big integers, preventing excessively
 * large numbers from affecting computational efficiency.
 * Represented as a BigInt to avoid precision loss.
 */
export const RANDOM_RANGE_DIVISOR = 200000000000000000000000n;