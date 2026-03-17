/**
 *
 * Utility Functions Module
 *
 * This file provides general-purpose helper functions, including type conversion,
 * cryptographic computations, random number generation, etc.
 * All functions are pure and have no external side effects, facilitating testing and reuse.
 * 
 */
import * as crypto from 'crypto';

// ============ Helper Functions ============

/**
 * Convert BigInt to hexadecimal byte string
 * @param {BigInt} value - Big integer to convert
 * @returns {string} Hexadecimal string prefixed with "0x"
 */
export const bigIntToBytes = (value: bigint) => {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;  // Pad to even length
  return '0x' + hex;
};

/**
 * Convert hexadecimal string to BigInt
 * @param {string} hexString - Hexadecimal string
 * @returns {BigInt} Converted big integer
 */
export const hexToBigInt = (hexString: string) => {
  if (!hexString || hexString === '0x') return 0n;
  hexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
  return hexString.length === 0 ? 0n : BigInt('0x' + hexString);
};

/**
 * Modular exponentiation (base^exponent mod modulus)
 * @param {BigInt} base - Base number
 * @param {BigInt} exponent - Exponent
 * @param {BigInt} modulus - Modulus
 * @returns {BigInt} Computation result
 */
export const modPow = (base: bigint, exponent: bigint, modulus: bigint) => {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  let exp = BigInt(exponent);

  while (exp > 0n) {
      if (exp & 1n) result = (result * base) % modulus;
      exp >>= 1n;
      base = (base * base) % modulus;
  }
  return result;
};

/**
 * Compute modular inverse (a^(-1) mod m)
 * @param {BigInt} a - Number to compute inverse for
 * @param {BigInt} m - Modulus
 * @returns {BigInt} Modular inverse
 */
export const modInverse = (a: bigint, m: bigint) => {
  let [m0, x, y] = [m, 1n, 0n];
  if (m === 1n) return 0n;

  while (a > 1n) {
      const q = a / m;
      [m, a] = [a % m, m];
      [x, y] = [y, x - q * y];
  }
  return x < 0n ? x + m0 : x;
};

/**
 * Generate a random big integer within a specified range
 * @param {BigInt} maxValue - Maximum value (exclusive)
 * @returns {BigInt} Random big integer within the range
 */
export const generateRandomBigIntInRange = (maxValue: bigint) => {
  const bitLength = Math.ceil(maxValue.toString(2).length / 8) + 2;
  while (true) {
      const randomBytes = crypto.randomBytes(bitLength);
      let randomValue = 0n;
      for (const byte of randomBytes) {
          randomValue = (randomValue << 8n) + BigInt(byte);
      }
      const result = randomValue % maxValue + 1n;
      if (result > 0n && result <= maxValue) return result;
  }
};

/**
 * Generate a random number coprime with n
 * @param {BigInt} n - Modulus
 * @param {number} bitLength - Bit length of random number
 * @returns {BigInt} Random number coprime with n
 */
export const generateRandomCoprime = (n: bigint, bitLength: number) => {
  const gcd = (a: bigint, b: bigint) => b ? gcd(b, a % b) : a;
  while (true) {
      let r = generateRandomBigIntInRange(n - 2n) + 2n;
      if (gcd(r, n) === 1n) return r;
  }
};