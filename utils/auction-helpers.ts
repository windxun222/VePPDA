import { network } from "hardhat";
const { ethers } = await network.connect();

import {
    bigIntToBytes,
    hexToBigInt,
    modPow,
    generateRandomBigIntInRange,
    generateRandomCoprime,
    modInverse,
} from "../utils/utils.js";
import { KEY_SIZE, RANDOM_BIT_LENGTH, RANDOM_RANGE_DIVISOR } from "../utils/constants.js";



// ============ Auction Operation Functions ============

/**
 * Submit a bid
 * @param {Contract} contract - Main contract instance
 * @param {Signer} bidder - Bidder signer object
 * @param {Object} bidderKeys - Bidder's Paillier key pair
 * @param {BigInt} auctionId - Auction ID
 * @param {string} bidValueEth - Bid amount (ETH string)
 * @returns {Object} Claim bid structure
 */
export async function submitBid(contract, bidder, bidderKeys, auctionId, bidValueEth) {
    // Convert ETH to Wei then to BigInt
    const bidBigInt = BigInt(ethers.parseEther(bidValueEth));
    // Generate random number r in range [1, n/RANDOM_RANGE_DIVISOR)
    const bidRandom = generateRandomBigIntInRange(
        bidderKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n
    );

    // Compute Paillier encrypted EPS values
    // eps.c1 = g^(bid * r) mod n^2
    // eps.c2 = g^r mod n^2
    const eps = {
        c1: bigIntToBytes(modPow(
            bidderKeys.publicKey.g,
            bidBigInt * bidRandom,
            bidderKeys.publicKey._n2
        )),
        c2: bigIntToBytes(modPow(
            bidderKeys.publicKey.g,
            bidRandom,
            bidderKeys.publicKey._n2
        ))
    };

    // Compute bid commitment
    const commitment = ethers.solidityPackedKeccak256(
        ["bytes", "bytes"],
        [bigIntToBytes(bidBigInt), bigIntToBytes(bidRandom)]
    );

    // Call contract to submit bid
    await contract.connect(bidder).claimBid(
        auctionId,
        {
            g: bigIntToBytes(bidderKeys.publicKey.g),
            n: bigIntToBytes(bidderKeys.publicKey.n)
        },
        bigIntToBytes(modPow(
            bidderKeys.publicKey.g,
            bidderKeys.privateKey.lambda,
            bidderKeys.publicKey._n2
        )),
        eps,
        commitment,
        { value: ethers.parseEther("0.1") }  // Deposit
    );

    return { bidBigInt, bidRandom };
}

/**
 * Challenge a bid (normal phase)
 * @param {Contract} contract - Main contract instance
 * @param {Signer} challenger - Challenger signer object
 * @param {BigInt} auctionId - Auction ID
 * @param {number} bidIndex - Index of the bid being challenged
 * @param {string} challValueEth - Challenge bid amount (ETH string)
 * @returns {Object} Challenge bid structure
 */
export async function performChallenge(contract, challenger, auctionId, bidIndex, challValueEth) {
    const challBigInt = BigInt(ethers.parseEther(challValueEth));

    // Get information of the challenged bid
    const validBids = await contract.getValidAuctionBids(auctionId);
    const challengedBid = validBids[bidIndex];

    const c1 = hexToBigInt(challengedBid.eps.c1);
    const c2 = hexToBigInt(challengedBid.eps.c2);
    const n = hexToBigInt(challengedBid.buyerPks.n);
    const n2 = n * n;

    // Generate random numbers a and r
    const a = generateRandomBigIntInRange(n / RANDOM_RANGE_DIVISOR - 1n);
    const r = generateRandomCoprime(n, RANDOM_BIT_LENGTH);

    // Compute challenge parameter c_a = c1^a * (c2^(a*chall))^(-1) * r^n mod n^2
    const c1Power = modPow(c1, a, n2);
    const c2Power = modPow(c2, a * challBigInt, n2);
    const rPower = modPow(r, n, n2);

    const c_a = (c1Power * modInverse(c2Power, n2) * rPower) % n2;

    // Compute challenge commitment
    const commitment = ethers.solidityPackedKeccak256(
        ["bytes", "bytes"],
        [bigIntToBytes(challBigInt), bigIntToBytes(a)]
    );

    // Call contract to challenge
    await contract.connect(challenger).challengeBid(
        auctionId,
        bidIndex,
        bigIntToBytes(c_a),
        commitment,
        { value: ethers.parseEther("0.1") },  // Challenge deposit
    );

    return { challBigInt, a };
}

/**
 * Respond to a challenge (normal phase)
 * @param {Contract} contract - Main contract instance
 * @param {Signer} responder - Responder signer object
 * @param {Object} responderKeys - Responder's Paillier key pair
 * @param {BigInt} auctionId - Auction ID
 * @param {number} bidIndex - Index of the challenged bid
 * @param {BigInt} bidRandom - Original bid random number r
 * @returns {number} Challenge result: 1 (challenge fails), -1 (challenge succeeds), 0 (equal)
 */
export async function respondToChallenge(contract, responder, responderKeys, auctionId, bidIndex, bidRandom) {

    const challengeDetails = await contract.getChallengeForBidClaim(auctionId, bidIndex);
    const challengeParam = hexToBigInt(challengeDetails.challengeParameters);

    // Decrypt challenge parameter: D(c_a) = L(c_a^λ mod n^2) * μ mod n
    const decrypted = modPow(challengeParam, responderKeys.privateKey.lambda, responderKeys.publicKey._n2);
    const l = (decrypted - 1n) / responderKeys.publicKey.n;
    const result = (l * responderKeys.privateKey.mu) % responderKeys.publicKey.n;

    // Normalize: result / r mod n
    const normalized = result * modInverse(bidRandom, responderKeys.publicKey.n) % responderKeys.publicKey.n;

    // Determine challenge result
    const r = normalized === 0n ? 0 :                     // equal
        (0n < normalized && normalized < responderKeys.publicKey.n / 2n) ? 1 : -1;  // challenge fails : challenge succeeds

    // Call contract to respond to challenge
    await contract.connect(responder).respondToChallenge(
        auctionId,
        bidIndex,
        bigIntToBytes(decrypted),
        r
    );

    return r;
}

/**
 * Replace bid after successful challenge
 * @param {Contract} contract - Main contract instance
 * @param {Signer} newBidder - New bidder signer object
 * @param {Object} newBidderKeys - New bidder's Paillier key pair
 * @param {BigInt} auctionId - Auction ID
 * @param {number} challengedIndex - Index of the challenged bid
 * @param {string} BidValueEth - New bid amount (ETH string)
 * @param {BigInt} BidRandom - New bid random number
 * @returns {Object} Claim bid structure
 */
export async function replaceBidAfterChallenge(contract, newBidder, newBidderKeys, auctionId, challengedIndex, BidValueEth, BidRandom) {
    const BidBigInt = BigInt(ethers.parseEther(BidValueEth));

    // Compute EPS values for new bid
    const eps = {
        c1: bigIntToBytes(modPow(
            newBidderKeys.publicKey.g,
            BidBigInt * BidRandom,
            newBidderKeys.publicKey._n2
        )),
        c2: bigIntToBytes(modPow(
            newBidderKeys.publicKey.g,
            BidRandom,
            newBidderKeys.publicKey._n2
        ))
    };

    // Compute new bid commitment
    const commitment = ethers.solidityPackedKeccak256(
        ["bytes", "bytes"],
        [bigIntToBytes(BidBigInt), bigIntToBytes(BidRandom)]
    );

    // Call contract to replace bid
    await contract.connect(newBidder).claimBidAfterSuccessfulChallenge(
        auctionId,
        challengedIndex,
        {
            g: bigIntToBytes(newBidderKeys.publicKey.g),
            n: bigIntToBytes(newBidderKeys.publicKey.n)
        },
        bigIntToBytes(modPow(
            newBidderKeys.publicKey.g,
            newBidderKeys.privateKey.lambda,
            newBidderKeys.publicKey._n2
        )),
        eps,
        commitment,
        { value: ethers.parseEther("0.1") },  // Deposit
    );

    return { BidBigInt, BidRandom };
}

/**
 * Initiate final challenge (settlement phase)
 * @param {Contract} contract - Main contract instance
 * @param {Signer} challenger - Challenger signer object (later slot bidder)
 * @param {BigInt} auctionId - Auction ID
 * @param {number} bidIndex - Index of the bid being challenged
 * @param {string} challValueEth - Challenge bid amount (ETH string)
 * @returns {Object} Challenge parameters
 */
export async function performFinalChallenge(contract, challenger, auctionId, bidIndex, challValueEth) {
    const challBigInt = BigInt(ethers.parseEther(challValueEth));

    // Get information of the challenged bid
    const validBids = await contract.getValidAuctionBids(auctionId);
    const challengedBid = validBids[bidIndex];

    const c1 = hexToBigInt(challengedBid.eps.c1);
    const c2 = hexToBigInt(challengedBid.eps.c2);
    const n = hexToBigInt(challengedBid.buyerPks.n);
    const n2 = n * n;

    // Generate random numbers a and r
    const a = generateRandomBigIntInRange(n / RANDOM_RANGE_DIVISOR - 1n);
    const r = generateRandomCoprime(n, RANDOM_BIT_LENGTH);

    // Compute challenge parameter c_a = c1^a * (c2^(a*chall))^(-1) * r^n mod n^2
    const c1Power = modPow(c1, a, n2);
    const c2Power = modPow(c2, a * challBigInt, n2);
    const rPower = modPow(r, n, n2);

    const c_a = (c1Power * modInverse(c2Power, n2) * rPower) % n2;

    // Compute challenge commitment
    const commitment = ethers.solidityPackedKeccak256(
        ["bytes", "bytes"],
        [bigIntToBytes(challBigInt), bigIntToBytes(a)]
    );

    // Call contract to initiate final challenge
    await contract.connect(challenger).challengeBidFinal(
        auctionId,
        bigIntToBytes(c_a),
        commitment
    );

    console.log(`${challenger.address.substring(0, 10)}... initiated final challenge successfully, bid: ${challValueEth} ETH`);

    return { challBigInt, a, c_a };
}

/**
 * Respond to final challenge (settlement phase)
 * @param {Contract} contract - Main contract instance
 * @param {Signer} responder - Responder signer object (earlier slot bidder)
 * @param {Object} responderKeys - Responder's Paillier key pair
 * @param {BigInt} auctionId - Auction ID
 * @param {BigInt} bidRandom - Original bid random number r
 * @returns {number} Challenge result: 1 (challenge fails), -1 (challenge succeeds), 0 (equal)
 */
export async function respondToFinalChallenge(contract, responder, responderKeys, auctionId, bidRandom) {
    // Get final challenge parameters
    const challengeDetails = await contract.getChallengeForBidClaim(auctionId, 0);
    const challengeParam = hexToBigInt(challengeDetails.challengeParameters);

    // Decrypt challenge parameter: D(c_a) = L(c_a^λ mod n^2) * μ mod n
    const decrypted = modPow(challengeParam, responderKeys.privateKey.lambda, responderKeys.publicKey._n2);
    const l = (decrypted - 1n) / responderKeys.publicKey.n;
    const result = (l * responderKeys.privateKey.mu) % responderKeys.publicKey.n;

    // Normalize: result / r mod n
    const normalized = result * modInverse(bidRandom, responderKeys.publicKey.n) % responderKeys.publicKey.n;

    // Determine challenge result
    const r = normalized === 0n ? 0 :                     // equal
        (0n < normalized && normalized < responderKeys.publicKey.n / 2n) ? 1 : -1;  // challenge fails : challenge succeeds

    // Call contract to respond to final challenge
    await contract.connect(responder).respondToChallengeFinal(
        auctionId,
        bigIntToBytes(decrypted),
        r
    );

    const resultText = r === -1 ? "challenge succeeds" : r === 1 ? "challenge fails" : "bids equal";
    console.log(`${responder.address.substring(0, 10)}... responded to final challenge: ${resultText}`);

    return r;
}


/**
 * Generate reserve price challenge parameters
 * @param {Object} sellerKeys - Seller's Paillier key pair
 * @param {BigInt} sellerReserveBigInt - Seller's reserve price
 * @param {BigInt} sellerRandom - Seller's reserve price random number
 * @param {BigInt} challengerBidBigInt - Challenger's bid
 * @returns {Object} Challenge parameters
 */
export function generateReserveChallengeParams(sellerKeys, sellerReserveBigInt, sellerRandom, challengerBidBigInt) {
    console.log(`[Generate Challenge] Generating challenge parameters...`);

    const a = generateRandomBigIntInRange(sellerKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n);
    const r = generateRandomCoprime(sellerKeys.publicKey.n, RANDOM_BIT_LENGTH);

    const c1 = modPow(
        sellerKeys.publicKey.g,
        sellerReserveBigInt * sellerRandom,
        sellerKeys.publicKey._n2
    );
    const c2 = modPow(
        sellerKeys.publicKey.g,
        sellerRandom,
        sellerKeys.publicKey._n2
    );
    const n2 = sellerKeys.publicKey.n * sellerKeys.publicKey.n;

    // Compute challenge parameter
    const c1Power = modPow(c1, a, n2);
    const c2Power = modPow(c2, a * challengerBidBigInt, n2);
    const rPower = modPow(r, sellerKeys.publicKey.n, n2);

    const c_a = (c1Power * modInverse(c2Power, n2) * rPower) % n2;
    // ethers v6: use solidityPackedKeccak256 instead of utils.solidityKeccak256
    const commitment = ethers.solidityPackedKeccak256(
        ["bytes", "bytes"],
        [bigIntToBytes(challengerBidBigInt), bigIntToBytes(a)]
    );

    console.log(`[Generate Challenge] Completed - challenge amount: ${ethers.formatEther(challengerBidBigInt)} ETH`);

    return {
        challengeParameters: bigIntToBytes(c_a),
        commitment: commitment,
        a: a,
        challengerBidBigInt: challengerBidBigInt
    };
}