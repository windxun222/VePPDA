// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BigNumbers.sol";

/**
 * @title PaillierCommitmentVerifier - Paillier commitment verification contract using big number arithmetic
 * @notice Supports on-chain verification of seller reserve price and buyer bid commitments, using the BigNumbers library to handle parameters of arbitrary size
 */
library Verifier {
    /// @notice Minimum byte length requirement for the Paillier modulus N, ensuring sufficient security
    uint256 public constant MIN_MODULUS_SIZE = 64;

    /// @notice Safety factor for randomness range check
    uint256 public constant RANDOMNESS_BOUND_MULTIPLIER = 2 * 10 ** 22;

    using BigNumbers for BigNumber;

    /**
     * @dev Converts a uint256 to its minimal byte representation (big-endian, no leading zeros)
     * @param value The uint256 value to convert
     * @return minimalBytes The resulting minimal byte array
     * @notice Special handling for zero value (returns single byte 0x00); otherwise removes all leading zeros
     */
    function uint256ToMinimalBytes(
        uint256 value
    ) public pure returns (bytes memory minimalBytes) {
        // Special case for zero
        if (value == 0) {
            minimalBytes = new bytes(1);
            minimalBytes[0] = 0x00;
            return minimalBytes;
        }

        // Calculate required byte length
        uint256 byteCount;
        uint256 temp = value;
        while (temp != 0) {
            byteCount++;
            temp >>= 8;
        }

        // Fill bytes (big-endian)
        minimalBytes = new bytes(byteCount);
        for (uint256 i = byteCount; i > 0; i--) {
            minimalBytes[i - 1] = bytes1(uint8(value & 0xFF));
            value >>= 8;
        }
    }

    /**
     * @dev Verifies the consistency of a hash commitment
     * @param storedCommitmentHash The commitment hash stored on-chain
     * @param revealedBidValue The revealed bid amount (in wei)
     * @param revealedRandomness The revealed randomness (byte array)
     * @return isValid Whether the commitment verification passes
     * @notice Calculation: keccak256(minimalBytes(bid) || randomness)
     */
    function verifyHashCommitment(
        bytes32 storedCommitmentHash,
        uint256 revealedBidValue,
        bytes memory revealedRandomness
    ) public pure returns (bool isValid) {
        bytes memory bidBytes = uint256ToMinimalBytes(revealedBidValue);
        bytes32 computedCommitment = keccak256(
            abi.encodePacked(bidBytes, revealedRandomness)
        );
        return computedCommitment == storedCommitmentHash;
    }

    /**
     * @dev Checks if randomness is within a safe range
     * @param modulus Paillier modulus N
     * @param revealedRandomness The revealed randomness r
     * @return isInSafeRange Whether the randomness satisfies safety conditions
     * @notice Verification condition: r * K < N, where K is the safety factor
     *         Ensures randomness is sufficiently large but not close to the modulus boundary
     */
    function isRandomnessInSafeRange(
        bytes memory modulus,
        bytes memory revealedRandomness
    ) public view returns (bool isInSafeRange) {
        BigNumber memory modulusBn = BigNumbers.init(modulus, false);
        BigNumber memory randomnessBn = BigNumbers.init(
            revealedRandomness,
            false
        );
        BigNumber memory boundMultiplierBn = BigNumbers.init(
            RANDOMNESS_BOUND_MULTIPLIER,
            false
        );

        // Compute r * K
        BigNumber memory randomnessTimesBound = BigNumbers.mul(
            randomnessBn,
            boundMultiplierBn
        );

        // Check r * K < N
        return BigNumbers.lt(randomnessTimesBound, modulusBn);
    }

    /**
     * @dev Verifies the correctness of Paillier encryption
     * @param generator Paillier public key parameter g (big-endian bytes)
     * @param modulus Paillier modulus N (big-endian bytes)
     * @param encryptedBid Encrypted bid c1
     * @param encryptedRandomness Encrypted randomness c2
     * @param revealedBidValue The revealed bid amount
     * @param revealedRandomness The revealed randomness r
     * @return isEncryptionValid Whether the encryption verification passes
     * @notice Verifies two conditions:
     *         1. c2 == g^r mod N²
     *         2. c1 == c2^bid mod N²
     */
    function verifyPaillierEncryption(
        bytes memory generator,
        bytes memory modulus,
        bytes memory encryptedBid,
        bytes memory encryptedRandomness,
        uint256 revealedBidValue,
        bytes memory revealedRandomness
    ) public view returns (bool isEncryptionValid) {
        // Initialize all big numbers (all positive)
        BigNumber memory generatorBn = BigNumbers.init(generator, false);
        BigNumber memory modulusBn = BigNumbers.init(modulus, false);
        BigNumber memory randomnessBn = BigNumbers.init(
            revealedRandomness,
            false
        );
        BigNumber memory bidValueBn = BigNumbers.init(
            uint256ToMinimalBytes(revealedBidValue),
            false
        );

        // Compute modulus N²
        BigNumber memory modulusSquared = modulusBn.mul(modulusBn);

        // Verify c2 == g^r mod N²
        BigNumber memory computedEncryptedRandomness = generatorBn.modexp(
            randomnessBn,
            modulusSquared
        );
        BigNumber memory storedEncryptedRandomness = BigNumbers.init(
            encryptedRandomness,
            false
        );
        if (!computedEncryptedRandomness.eq(storedEncryptedRandomness)) {
            return false;
        }

        // Verify c1 == c2^bid mod N²
        BigNumber memory computedEncryptedBid = storedEncryptedRandomness
            .modexp(bidValueBn, modulusSquared);
        BigNumber memory storedEncryptedBid = BigNumbers.init(
            encryptedBid,
            false
        );

        return computedEncryptedBid.eq(storedEncryptedBid);
    }


    /**
     * @dev Verifies the correctness of the Paillier private key parameter μ
     * @param generator Public key parameter g
     * @param modulus Modulus N
     * @param privateKeyParameterMu Private key parameter μ
     * @param privateKeyParameterLambda Private key parameter λ
     * @return isMuValid Whether μ verification passes
     * @notice Verifies Paillier private key derivation conditions:
     *         1. Compute u = g^λ mod N²
     *         2. Verify (u-1) % N == 0
     *         3. Verify μ * (u-1) ≡ N (mod N²)
     */
    function verifyPrivateKeyParameterMu(
        bytes memory generator,
        bytes memory modulus,
        bytes memory privateKeyParameterMu,
        bytes memory privateKeyParameterLambda
    ) public view returns (bool isMuValid) {
        // Initialize big numbers
        BigNumber memory generatorBn = BigNumbers.init(generator, false);
        BigNumber memory modulusBn = BigNumbers.init(modulus, false);
        BigNumber memory muBn = BigNumbers.init(privateKeyParameterMu, false);
        BigNumber memory lambdaBn = BigNumbers.init(
            privateKeyParameterLambda,
            false
        );

        // Compute N²
        BigNumber memory modulusSquared = modulusBn.mul(modulusBn);

        // Compute u = g^λ mod N²
        BigNumber memory uBn = generatorBn.modexp(lambdaBn, modulusSquared);

        // Compute u-1
        BigNumber memory one = BigNumbers.one();
        BigNumber memory uMinusOne = uBn.sub(one);

        // Verify (u-1) is divisible by N
        BigNumber memory remainder = uMinusOne.mod(modulusBn);
        if (!remainder.eq(BigNumbers.zero())) {
            return false;
        }

        // Verify μ * (u-1) ≡ N (mod N²)
        BigNumber memory leftSide = muBn.mul(uMinusOne);
        BigNumber memory leftSideModN2 = leftSide.mod(modulusSquared);

        return leftSideModN2.eq(modulusBn);
    }

    /**
     * @dev Verifies a false claim challenge
     * @param modulus Modulus N_b
     * @param encryptedBid Encrypted bid c_b1
     * @param encryptedRandomness Encrypted randomness c_b2
     * @param storedEncryptedBid Stored encrypted bid c_a
     * @param revealedBidValue Revealed bid P_a
     * @param challengeValue Challenge value a
     * @param challengeRandomness Challenge randomness r_a
     * @return isChallengeValid Whether the challenge verification passes
     * @notice Verifies the equation:
     *         c_a * c_b2^{a * P_a} ≡ c_b1^a * r_a^{N_b} (mod N_b²)
     */
    function verifyFalseClaimChallenge(
        bytes memory modulus,
        bytes memory encryptedBid,
        bytes memory encryptedRandomness,
        bytes memory storedEncryptedBid,
        uint256 revealedBidValue,
        bytes memory challengeValue,
        bytes memory challengeRandomness
    ) public view returns (bool isChallengeValid) {
        // Initialize all big numbers
        BigNumber memory modulusBn = BigNumbers.init(modulus, false);
        BigNumber memory encryptedBidBn = BigNumbers.init(
            encryptedBid,
            false
        );
        BigNumber memory encryptedRandomnessBn = BigNumbers.init(
            encryptedRandomness,
            false
        );
        BigNumber memory sellerEncryptedBidBn = BigNumbers.init(
            storedEncryptedBid,
            false
        );
        BigNumber memory challengeValueBn = BigNumbers.init(
            challengeValue,
            false
        );
        BigNumber memory challengeRandomnessBn = BigNumbers.init(
            challengeRandomness,
            false
        );
        BigNumber memory bidValueBn = BigNumbers.init(
            uint256ToMinimalBytes(revealedBidValue),
            false
        );

        // Compute modulus N_b²
        BigNumber memory modulusSquared = modulusBn.mul(modulusBn);

        // Compute left side: c_a * c_b2^{a * P_a} mod N_b²
        BigNumber memory exponent = challengeValueBn.mul(bidValueBn);
        BigNumber memory encryptedRandomnessExp = encryptedRandomnessBn.modexp(
            exponent,
            modulusSquared
        );
        BigNumber memory leftSide = sellerEncryptedBidBn
            .mul(encryptedRandomnessExp)
            .mod(modulusSquared);

        // Compute right side: c_b1^a * r_a^{N_b} mod N_b²
        BigNumber memory term1 = encryptedBidBn.modexp(
            challengeValueBn,
            modulusSquared
        );
        BigNumber memory term2 = challengeRandomnessBn.modexp(
            modulusBn,
            modulusSquared
        );
        BigNumber memory rightSide = term1.mul(term2).mod(modulusSquared);

        return leftSide.eq(rightSide);
    }

    /**
     * @dev Simplified verification of gcd(g, N²) = 1
     * @param generator Public key parameter g
     * @param modulus Modulus N
     * @return isGcdValid Whether the gcd verification passes
     * @notice Indirectly verified by checking if g^N mod N² is non-zero
     *         If the result is zero, then gcd(g, N²) ≠ 1
     */
    function verifyGeneratorModulusGcd(
        bytes memory generator,
        bytes memory modulus
    ) public view returns (bool isGcdValid) {
        BigNumber memory generatorBn = BigNumbers.init(generator, false);
        BigNumber memory modulusBn = BigNumbers.init(modulus, false);
        BigNumber memory modulusSquared = modulusBn.mul(modulusBn);

        // Compute g^N mod N²
        BigNumber memory result = generatorBn.modexp(modulusBn, modulusSquared);

        // Check if result is zero
        return !BigNumbers.isZero(result);
    }

    /**
     * @dev Validates the Paillier public key parameters (optional)
     * @param sellerGenerator Seller's public key parameter g_s
     * @param sellerModulus Seller's modulus N_s
     * @return validationResult Validation result code: 0 = pass, non-zero = failure
     * @return failureReason Description of the failure reason
     * @notice Performs the following security checks:
     *         1. N size at least MIN_MODULUS_SIZE bytes
     *         2. 1 < g < N²
     *         3. g ≠ N + 1 (prevent malicious construction)
     *         4. gcd(g, N²) = 1 (indirectly verified via g^N mod N² ≠ 0)
     *         5. N is odd (quickly exclude even moduli)
     */
    function validatePaillierParameters(
        bytes memory sellerGenerator,
        bytes memory sellerModulus
    )
        public
        view
        returns (uint8 validationResult, string memory failureReason)
    {
        // 1. Check modulus size
        if (sellerModulus.length < MIN_MODULUS_SIZE) {
            return (1, "Modulus N_s is too small for security");
        }

        // Initialize big numbers
        BigNumber memory generatorBn = BigNumbers.init(sellerGenerator, false);
        BigNumber memory modulusBn = BigNumbers.init(sellerModulus, false);
        BigNumber memory one = BigNumbers.one();

        // 2. Check 1 < g < N²
        if (!BigNumbers.gt(generatorBn, one)) {
            return (2, "Generator g_s must be greater than 1");
        }

        BigNumber memory modulusSquared = modulusBn.mul(modulusBn);
        if (!BigNumbers.lt(generatorBn, modulusSquared)) {
            return (2, "Generator g_s must be less than N_s^2");
        }

        // 3. Check g ≠ N + 1 (prevent malicious construction)
        BigNumber memory modulusPlusOne = modulusBn.add(one);
        if (generatorBn.eq(modulusPlusOne)) {
            return (
                3,
                "Generator g_s cannot equal N_s + 1 (malicious construction)"
            );
        }

        // 4. Simplified verification of gcd(g, N²) = 1
        BigNumber memory gcdTestResult = generatorBn.modexp(
            modulusBn,
            modulusSquared
        );
        if (BigNumbers.isZero(gcdTestResult)) {
            return (4, "gcd(g_s, N_s^2) != 1 (invalid generator)");
        }

        // 5. Quick check if N is even
        bytes memory lastByte = new bytes(1);
        lastByte[0] = sellerModulus[sellerModulus.length - 1];
        BigNumber memory lastByteBn = BigNumbers.init(lastByte, false);
        BigNumber memory two = BigNumbers.init(2, false);

        if (lastByteBn.mod(two).eq(BigNumbers.zero())) {
            return (1, "Modulus N_s is even (invalid Paillier modulus)");
        }

        // All checks passed
        return (0, "All Paillier parameter checks passed");
    }
}