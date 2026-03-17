/**
 * 
 * Main Test Suite File - VEPPDA Protocol End-to-End Test
 *
 * This file serves as the entry point for the entire test process, responsible for organizing 
 * and executing the complete auction flow test.
 * All utility functions, constants, logging, and contract operations have been modularized,
 * leaving only the test structure and process orchestration here.
 * Dependencies on external modules:
 * 
 * - utils.js: Cryptographic and helper functions
 * - logger.js: Colored log output
 * - auction-helpers.js: Contract interaction wrappers
 */

import { expect } from "chai";
import { network } from "hardhat";
import * as paillier from 'paillier-bigint';
const { ethers } = await network.connect();


import {
  bigIntToBytes,
  hexToBigInt,
  modPow,
  generateRandomBigIntInRange,
  generateRandomCoprime,
  modInverse,
} from "../utils/utils.js";

import { logger } from "../utils/logger.js";

import {
  submitBid,
  performChallenge,
  respondToChallenge,
  replaceBidAfterChallenge,
  performFinalChallenge,
  respondToFinalChallenge,
  generateReserveChallengeParams,
} from "../utils/auction-helpers.js";

import { KEY_SIZE, RANDOM_BIT_LENGTH, RANDOM_RANGE_DIVISOR } from "../utils/constants.js";
// ==================================


// ============ Main Test Suite ============

describe("VePPDA - Complete Auction Flow Test", () => {
    let mainContract;        // Main contract
    let auctionContract;     // Auction contract
    let settlementContract;  // Settlement contract
    let disputeContract;     // Dispute contract
    let verifierContract;    // Verifier contract
    
    // Test accounts
    let seller, bidderA, bidderB, bidderC, bidderD, bidderE, challenger, accuser1, accuser2;
    let auctionId;          // Auction ID
    
    // Keys for all parties
    let sellerKeys, bidderAKeys, bidderBKeys, bidderCKeys, bidderDKeys, bidderEKeys;
    let sellerReserveBigInt, sellerRandom; // Seller reserve price and random number

    // Before each test case
    beforeEach(async () => {
        // Get test accounts
        [seller, bidderA, bidderB, bidderC, bidderD, bidderE, challenger, accuser1, accuser2] = await ethers.getSigners();

        logger.stage("Deploying Smart Contracts");
        logger.action("System", "Starting contract deployment...");

        // Deploy Verifier library
        const Verifier = await ethers.getContractFactory("Verifier");
        verifierContract = await Verifier.deploy();
        await verifierContract.waitForDeployment();
        logger.success("Verifier library deployed");
        const verifierAddress = await verifierContract.getAddress();
        // Deploy Auction contract
        const AuctionContractFactory = await ethers.getContractFactory("VePPDA_Auction");
        auctionContract = await AuctionContractFactory.deploy();
        await auctionContract.waitForDeployment();
        logger.success("Auction contract deployed");
        const auctionAddress = await auctionContract.getAddress();
        // Deploy Settlement contract
        const SettlementContract = await ethers.getContractFactory("VePPDA_Settlement");
        settlementContract = await SettlementContract.deploy(auctionAddress);
        await settlementContract.waitForDeployment();
        logger.success("Settlement contract deployed");
        const settlementAddress = await settlementContract.getAddress();
        // Deploy Dispute contract (linking Verifier library)
        const DisputeContract = await ethers.getContractFactory("VePPDA_Dispute", {
            libraries: {
                Verifier: verifierAddress,
            },
        });
        disputeContract = await DisputeContract.deploy(auctionAddress, settlementAddress);
        await disputeContract.waitForDeployment();
        logger.success("Dispute contract deployed");
        const disputeAddress = await disputeContract.getAddress();
        // Deploy Main contract
        const MainContract = await ethers.getContractFactory("VePPDA_Main");
        mainContract = await MainContract.deploy(auctionAddress, disputeAddress, settlementAddress);
        await mainContract.waitForDeployment();
        logger.success("Main contract deployed");

        logger.separator();
        logger.action("System", "Generating Paillier key pairs...");

        // Generate Paillier keys for all parties
        sellerKeys = await paillier.generateRandomKeys(KEY_SIZE);
        bidderAKeys = await paillier.generateRandomKeys(KEY_SIZE);
        bidderBKeys = await paillier.generateRandomKeys(KEY_SIZE);
        bidderCKeys = await paillier.generateRandomKeys(KEY_SIZE);
        bidderDKeys = await paillier.generateRandomKeys(KEY_SIZE);
        bidderEKeys = await paillier.generateRandomKeys(KEY_SIZE);
        logger.success("Paillier key pairs generated");

        // Create auction parameters
        sellerReserveBigInt = BigInt(ethers.parseEther("2.5"));  // Reserve price 2.5 ETH
        sellerRandom = generateRandomBigIntInRange(sellerKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n);

        const auctionParams = {
            info: "Precious Artwork NFT Auction",  // Auction description
            startPrice: ethers.parseEther("2.0"),  // Starting price 2 ETH
            duration: 3600,  // Duration 1 hour
            length: 2,       // Buffer length 2
            pks: {          // Seller public key
                g: bigIntToBytes(sellerKeys.publicKey.g),
                n: bigIntToBytes(sellerKeys.publicKey.n)
            },
            verifyParameters: bigIntToBytes(modPow(  // Verification parameter g^λ mod n^2
                sellerKeys.publicKey.g,
                sellerKeys.privateKey.lambda,
                sellerKeys.publicKey._n2
            )),
            eps: {  // Encrypted reserve price
                c1: bigIntToBytes(modPow(
                    sellerKeys.publicKey.g,
                    sellerReserveBigInt * sellerRandom,
                    sellerKeys.publicKey._n2
                )),
                c2: bigIntToBytes(modPow(
                    sellerKeys.publicKey.g,
                    sellerRandom,
                    sellerKeys.publicKey._n2
                ))
            },
            commitment: ethers.solidityPackedKeccak256(  // Reserve price commitment
                ["bytes", "bytes"],
                [bigIntToBytes(sellerReserveBigInt), bigIntToBytes(sellerRandom)]
            )
        };

        logger.separator();
        logger.action("Seller", "Creating auction...");

        // Create auction via main contract
        const createTx = await mainContract.connect(seller).createAuction(auctionParams, {
            value: ethers.parseEther("0.1")  // Creation deposit
        });

        // ethers v6 event parsing
        const receipt = await createTx.wait();
        // Parse logs using contract interface to find AuctionCreated event
        const event = receipt.logs
            .map(log => mainContract.interface.parseLog(log))
            .find(event => event && event.name === 'AuctionCreated');
        auctionId = event.args.auctionId;

        logger.success(`Auction created successfully, Auction ID: ${auctionId}`);
        logger.info(`Starting price: 2.0 ETH | Reserve price: 2.5 ETH | Buffer length: 2`);
    });

    // ============ Main Test Cases ============

    /**
     * Test complete competitive flow with five bidders, including reserve challenge:
     * 1. Multiple rounds of bidding and challenges
     * 2. Failed challenges and successful challenges
     * 3. Auction settlement and final challenge
     * 4. Reserve price challenge
     * 5. Verify final winner
     */
    it("Complete auction flow test", async () => {
        logger.stage("Phase 1: Initial Bids");

        // Bidder A bids 2.3 ETH
        logger.action("BidderA", "Submitting bid", "2.3 ETH");
        const { bidRandom: randomA } = await submitBid(mainContract, bidderA, bidderAKeys, auctionId, "2.3");
        logger.success("BidderA bid successful");

        // Bidder B bids 2.4 ETH (fills buffer)
        logger.action("BidderB", "Submitting bid", "2.4 ETH");
        const { bidRandom: randomB } = await submitBid(mainContract, bidderB, bidderBKeys, auctionId, "2.4");
        logger.success("BidderB bid successful");

        // Verify current number of valid bids
        let validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Current valid bids: ${validBids.length}/2`);
        expect(validBids.length).to.equal(2);  // Buffer full

        logger.stage("Phase 2: Failed Challenge");

        // Bidder C challenges B's bid with 2.2 ETH (should fail)
        logger.action("BidderC", "Challenging BidderB's bid", "2.2 ETH (below current bid)");
        const bidderBIndex = 1;
        await performChallenge(mainContract, bidderC, auctionId, bidderBIndex, "2.2");

        // B responds to challenge (expected r=1, challenge fails)
        logger.action("BidderB", "Responding to challenge");
        const rC = await respondToChallenge(mainContract, bidderB, bidderBKeys, auctionId, bidderBIndex, randomB);

        if (rC === 1) {
            logger.success("Challenge failed: BidderB's bid retained");
        } else if (rC === -1) {
            logger.error("Challenge succeeded: BidderB's bid removed");
        } else {
            logger.info("Challenge result: bids equal");
        }

        expect(rC).to.equal(1);  // Challenge fails, B's bid retained

        // Verify valid bids count unchanged
        validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Valid bids after challenge: ${validBids.length}/2`);
        expect(validBids.length).to.equal(2);

        logger.stage("Phase 3: Successful Challenge");

        // Bidder D challenges B's bid with 2.7 ETH (should succeed)
        logger.action("BidderD", "Challenging BidderB's bid", "2.7 ETH (above current bid)");
        const { a: randomD } = await performChallenge(mainContract, bidderD, auctionId, bidderBIndex, "2.7");

        // B responds to challenge (expected r=-1, challenge succeeds)
        logger.action("BidderB", "Responding to challenge");
        const rD = await respondToChallenge(mainContract, bidderB, bidderBKeys, auctionId, bidderBIndex, randomB);

        if (rD === 1) {
            logger.error("Challenge failed: BidderB's bid retained");
        } else if (rD === -1) {
            logger.success("Challenge succeeded: BidderB's bid removed");
        } else {
            logger.info("Challenge result: bids equal");
        }

        expect(rD).to.equal(-1);  // Challenge succeeds, B's bid invalidated

        // Verify B's bid removed
        validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Valid bids after challenge: ${validBids.length}/2`);
        expect(validBids.length).to.equal(1);  // Only A's bid remains

        // D replaces B's bid slot
        logger.action("BidderD", "Replacing bid slot", "2.7 ETH");
        await replaceBidAfterChallenge(mainContract, bidderD, bidderDKeys, auctionId, bidderBIndex, "2.7", randomD);
        logger.success("BidderD replaced bid successfully");

        // Verify buffer full again
        validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Valid bids after replacement: ${validBids.length}/2`);
        expect(validBids.length).to.equal(2);  // A and D bids

        logger.stage("Phase 4: Second Round Challenge");

        // Bidder E challenges D's bid with 3.0 ETH (should succeed)
        logger.action("BidderE", "Challenging BidderD's bid", "3.0 ETH (above current bid)");
        const bidderDIndex = bidderBIndex;
        const { a: randomE } = await performChallenge(mainContract, bidderE, auctionId, bidderDIndex, "3.0");

        // D responds to challenge (expected r=-1, challenge succeeds)
        logger.action("BidderD", "Responding to challenge");
        const rE = await respondToChallenge(mainContract, bidderD, bidderDKeys, auctionId, bidderDIndex, randomD);

        if (rE === 1) {
            logger.error("Challenge failed: BidderD's bid retained");
        } else if (rE === -1) {
            logger.success("Challenge succeeded: BidderD's bid removed");
        } else {
            logger.info("Challenge result: bids equal");
        }

        expect(rE).to.equal(-1);  // Challenge succeeds, D's bid invalidated

        // Verify D's bid removed
        validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Valid bids after challenge: ${validBids.length}/2`);
        expect(validBids.length).to.equal(1);  // Only A's bid remains

        // E replaces D's bid slot
        logger.action("BidderE", "Replacing bid slot", "3.0 ETH");
        await replaceBidAfterChallenge(mainContract, bidderE, bidderEKeys, auctionId, bidderDIndex, "3.0", randomE);
        logger.success("BidderE replaced bid successfully");

        // Verify final buffer state
        validBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Final valid bids: ${validBids.length}/2`);
        expect(validBids.length).to.equal(2);  // A and E bids
        expect(validBids[1].bidder).to.equal(bidderE.address);  // E at index 1

        logger.stage("Phase 5: Auction Settlement");

        // Advance time to auction end (1 hour + 10 min buffer)
        logger.action("System", "Advancing time", "1 hour + 10 min buffer");
        await ethers.provider.send("evm_increaseTime", [3600 + 600]);
        await ethers.provider.send("evm_mine");
        logger.success("Time advanced, auction ended");

        // Seller settles auction, enters settlement challenge phase
        logger.action("Seller", "Settling auction");
        await mainContract.connect(seller).settleAuction(auctionId);
        logger.success("Auction entered settlement challenge phase");

        // Verify settlement state
        const settlement = await mainContract.getSettlementStage(auctionId);
        logger.info(`Settlement challenger: ${settlement.challenger.substring(0, 10)}... (BidderE)`);
        logger.info(`Challenged bidder: ${settlement.challengedBidder.substring(0, 10)}... (BidderA)`);
        expect(settlement.inSettlementChallenge).to.be.true;  // In settlement challenge phase
        expect(settlement.challenger).to.equal(bidderE.address);     // Challenger: later slot E
        expect(settlement.challengedBidder).to.equal(bidderA.address); // Challenged: earlier slot A

        logger.stage("Phase 6: Final Challenge");

        // E initiates final challenge
        logger.action("BidderE", "Initiating final challenge", "3.0 ETH vs 2.3 ETH");
        const bidderAIndex = 0;
        await performFinalChallenge(mainContract, bidderE, auctionId, bidderAIndex, "3.0");

        logger.stage("Phase 7: Final Challenge Response");

        logger.action("BidderA", "Responding to final challenge");
        const rFinalResp = await respondToFinalChallenge(mainContract, bidderA, bidderAKeys, auctionId, randomA);
        const resultText = rFinalResp === -1 ? "challenge succeeds" : rFinalResp === 1 ? "challenge fails" : "bids equal";
        console.log(`${bidderA}... responded to final challenge: ${resultText}`);
        // Verify challenge result
        expect(rFinalResp).to.equal(-1);  // Final challenge succeeds, E's bid higher

        logger.stage("Phase 8: Reserve Price Challenge");

        // Verify auction winner
     
        let winner = await mainContract.getAuctionWinner(auctionId);
        let settled = await mainContract.isAuctionSettled(auctionId);
        logger.info(`Auction winner: ${winner.substring(0, 10)}... (BidderE)`);
        logger.info(`Auction settled: ${settled}`);
        expect(winner).to.equal(bidderE.address);  // Winner should be E
        expect(settled).to.be.true;  // Auction should be settled

        // Winner initiates reserve price challenge (bid 3.0 ETH > reserve 2.5 ETH, expected to succeed)
        logger.action("BidderE", "Initiating reserve price challenge", "3.0 ETH > 2.5 ETH");
        const challengerBidBigInt = BigInt(ethers.parseEther("3.0"));
        const challengeParams = generateReserveChallengeParams(
            sellerKeys,
            sellerReserveBigInt,
            sellerRandom,
            challengerBidBigInt
        );

        await mainContract.connect(bidderE).challengeReserve(
            auctionId,
            challengeParams.challengeParameters,
            challengeParams.commitment,
            { value: ethers.parseEther("0.1") }
        );
        logger.success("Reserve price challenge submitted");

        // Verify challenge record
        const reserveChallenge = await mainContract.getReserveChallenge(auctionId);
        logger.info(`Challenger: ${reserveChallenge.challenger}`);
        logger.info(`Challenge status: ${reserveChallenge.isResolved ? 'Resolved' : 'Unresolved'}`);
        expect(reserveChallenge.challenger).to.equal(bidderE.address);
        expect(reserveChallenge.isResolved).to.be.false;

        // Seller responds to reserve challenge (challenge succeeds)
        logger.action("Seller", "Responding to reserve challenge");
        const m = bigIntToBytes(1n);
        const r = 0; // Challenge succeeds (winner's bid > reserve)

        await mainContract.connect(seller).respondToChallengeReserve(
            auctionId,
            m,
            r
        );
        logger.success("Reserve challenge response submitted");

        // Verify challenge result
        const updatedChallenge = await mainContract.getReserveChallenge(auctionId);
        logger.info(`Challenge status: ${updatedChallenge.isResolved ? 'Resolved' : 'Unresolved'}`);
        logger.info(`Challenge result: ${updatedChallenge.isSuccessful ? 'Success' : 'Failure'}`);
        
        expect(updatedChallenge.isResolved).to.be.true;
        expect(updatedChallenge.isSuccessful).to.be.true;

        logger.stage("Final Result Verification");

        // Verify final auction state (should succeed, winner is BidderE)
        const auctionFailed = await mainContract.isAuctionFailed(auctionId);
        winner = await mainContract.getAuctionWinner(auctionId);

        logger.info(`Auction status: ${auctionFailed ? 'Failed' : 'Succeeded'}`);
        logger.info(`Final winner: ${winner}`);

        expect(auctionFailed).to.be.false;
        expect(winner).to.equal(bidderE.address);

        logger.separator();
        logger.action("System", "All test cases executed - Complete flow with reserve challenge test succeeded!");
    });

    /**
     * Test complete dispute mechanism:
     * 1. Normal auction process
     * 2. Failed challenge
     * 3. Auction settlement
     * 4. Dispute handling (seller, bidder, challenger disputes)
     * 5. Deposit refunds
     */
    it("Should handle complete dispute scenario - including seller, bidder and challenger disputes", async () => {
        logger.stage("Complete Dispute Scenario Test");
        logger.info("Starting complete dispute scenario test");

        // ==================== Phase 1: Normal Auction Process ====================
        logger.stage("Phase 1: Normal Auction Process");
        logger.separator();

        // 1.1 Bidder A bids 2.5 ETH
        
        logger.action("Bidder A", "Submitting bid", "2.5 ETH");
        const bidAValue = "2.5";
        const bidABigInt = BigInt(ethers.parseEther(bidAValue));
        const bidARandom = generateRandomBigIntInRange(
            bidderAKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n
        );

        const epsA = {
            c1: bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidABigInt * bidARandom,
                bidderAKeys.publicKey._n2
            )),
            c2: bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidARandom,
                bidderAKeys.publicKey._n2
            ))
        };

        const commitmentA = ethers.solidityPackedKeccak256(
            ["bytes", "bytes"],
            [bigIntToBytes(bidABigInt), bigIntToBytes(bidARandom)]
        );

        await mainContract.connect(bidderA).claimBid(
            auctionId,
            {
                g: bigIntToBytes(bidderAKeys.publicKey.g),
                n: bigIntToBytes(bidderAKeys.publicKey.n)
            },
            bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidderAKeys.privateKey.lambda,
                bidderAKeys.publicKey._n2
            )),
            epsA,
            commitmentA,
            { value: ethers.parseEther("0.1") }
        );
        logger.success(`Bidder A (${bidderA.address.substring(0, 10)}...) bid ${bidAValue} ETH`);

        // 1.2 Bidder B bids 2.8 ETH
        logger.action("Bidder B", "Submitting bid", "2.8 ETH");
        const bidBValue = "2.8";
        const bidBBigInt = BigInt(ethers.parseEther(bidBValue));
        const bidBRandom = generateRandomBigIntInRange(
            bidderBKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n
        );

        const epsB = {
            c1: bigIntToBytes(modPow(
                bidderBKeys.publicKey.g,
                bidBBigInt * bidBRandom,
                bidderBKeys.publicKey._n2
            )),
            c2: bigIntToBytes(modPow(
                bidderBKeys.publicKey.g,
                bidBRandom,
                bidderBKeys.publicKey._n2
            ))
        };

        const commitmentB = ethers.solidityPackedKeccak256(
            ["bytes", "bytes"],
            [bigIntToBytes(bidBBigInt), bigIntToBytes(bidBRandom)]
        );

        await mainContract.connect(bidderB).claimBid(
            auctionId,
            {
                g: bigIntToBytes(bidderBKeys.publicKey.g),
                n: bigIntToBytes(bidderBKeys.publicKey.n)
            },
            bigIntToBytes(modPow(
                bidderBKeys.publicKey.g,
                bidderBKeys.privateKey.lambda,
                bidderBKeys.publicKey._n2
            )),
            epsB,
            commitmentB,
            { value: ethers.parseEther("0.1") }
        );
        logger.success(`Bidder B (${bidderB.address.substring(0, 10)}...) bid ${bidBValue} ETH`);

        // 1.3 Challenger challenges Bidder B's bid
        logger.action("Challenger", "Initiating challenge", "2.6 ETH (below current bid 2.8 ETH)");
        
        const validBids = await mainContract.getValidAuctionBids(auctionId);
        const bidBIndex = 1; // Bidder B's bid index

        const challengedN = hexToBigInt(validBids[bidBIndex].buyerPks.n);
        const falseChallengeValue = "2.6"; 

        const challengeBigInt = BigInt(ethers.parseEther(falseChallengeValue));
        const a = generateRandomBigIntInRange(challengedN / RANDOM_RANGE_DIVISOR - 1n);
        const r = generateRandomCoprime(challengedN, RANDOM_BIT_LENGTH);

        const c1 = hexToBigInt(validBids[bidBIndex].eps.c1);
        const c2 = hexToBigInt(validBids[bidBIndex].eps.c2);
        const n2 = challengedN * challengedN;

        const c1Power = modPow(c1, a, n2);
        const c2Power = modPow(c2, a * challengeBigInt, n2);
        const rPower = modPow(r, challengedN, n2);
        const c_a = (c1Power * modInverse(c2Power, n2) * rPower) % n2;

        const challengeCommitment = ethers.solidityPackedKeccak256(
            ["bytes", "bytes"],
            [bigIntToBytes(challengeBigInt), bigIntToBytes(a)]
        );

        await mainContract.connect(challenger).challengeBid(
            auctionId,
            bidBIndex,
            bigIntToBytes(c_a),
            challengeCommitment,
            { value: ethers.parseEther("0.1") }
        );
        logger.success(`Challenger (${challenger.address.substring(0, 10)}...) challenged Bidder B`);
        logger.info(`Challenge price: ${falseChallengeValue} ETH (actual bid: ${bidBValue} ETH)`);

        // 1.4 Bidder B responds to challenge
        logger.action("Bidder B", "Responding to challenge");
        
        const challengeDetails = await mainContract.getChallengeForBidClaim(auctionId, bidBIndex);
        const challengeParam = hexToBigInt(challengeDetails.challengeParameters);

        const decrypted = modPow(challengeParam, bidderBKeys.privateKey.lambda, bidderBKeys.publicKey._n2);
        const l = (decrypted - 1n) / bidderBKeys.publicKey.n;
        const result = (l * bidderBKeys.privateKey.mu) % bidderBKeys.publicKey.n;
        const normalized = result * modInverse(bidBRandom, bidderBKeys.publicKey.n) % bidderBKeys.publicKey.n;

        const challengeResult = normalized === 0n ? 0 :
            (0n < normalized && normalized < bidderBKeys.publicKey.n / 2n) ? 1 : -1;

        await mainContract.connect(bidderB).respondToChallenge(
            auctionId,
            bidBIndex,
            bigIntToBytes(decrypted),
            challengeResult
        );

        logger.success(`Challenge response completed`);
        logger.info(`Challenge result: ${challengeResult === 1 ? "Challenge failed" : "Challenge succeeded"}`);
        expect(challengeResult).to.equal(1); // Challenge should fail

        // ==================== Phase 2: Auction Settlement ====================
        logger.stage("Phase 2: Auction Settlement");
        logger.separator();

        // 2.1 Wait for auction end
        logger.action("System", "Waiting for auction to end");
        await ethers.provider.send("evm_increaseTime", [3600 + 600]); // Auction duration + challenge response time
        await ethers.provider.send("evm_mine");
        logger.success("Auction ended");

        // 2.2 Seller settles auction
        logger.action("Seller", "Settling auction");
        await mainContract.connect(seller).settleAuction(auctionId);
        
        const settlementStage = await mainContract.getSettlementStage(auctionId);
        logger.success("Auction settlement completed");
        logger.info(`Settlement phase: ${settlementStage.inSettlementChallenge ? "Final challenge phase" : "Settled"}`);
        logger.info(`Challenger: ${settlementStage.challenger}`);
        logger.info(`Challenged bidder: ${settlementStage.challengedBidder}`);

        // ==================== Phase 3: Dispute Handling ====================
        logger.stage("Phase 3: Dispute Handling");
        logger.separator();

        // 3.1 Case 1: Accuse seller of false reserve price (honest seller)
        logger.action("Accuser 1", "Accusing seller of false reserve price", "(seller honest)");
        
        // Accuser 1 accuses seller
        await mainContract.connect(accuser1).accuseSellerMalicious(auctionId, {
            value: ethers.parseEther("0.1")
        });
        logger.success(`Accuser 1 (${accuser1.address.substring(0, 10)}...) accused seller of false reserve price`);

        // Seller responds to dispute
        await mainContract.connect(seller).respondSellerDispute(
            auctionId,
            sellerReserveBigInt,
            bigIntToBytes(sellerRandom)
        );
        logger.success(`Seller (${seller.address.substring(0, 10)}...) responded to dispute`);

        // Check dispute result
        const sellerDisputeInfo = await mainContract.getSellerDisputeInfo(auctionId);
        logger.info(`Dispute result: ${sellerDisputeInfo.guilty ? "Seller guilty" : "Seller not guilty"}`);
        expect(sellerDisputeInfo.guilty).to.be.false;

        // 3.2 Case 2: Accuse bidder of false bid
        logger.action("Accuser 2", "Accusing bidder of false bid");
        
        // Get valid bids
        const finalBids = await mainContract.getValidAuctionBids(auctionId);
        logger.info(`Valid bids count: ${finalBids.length}`);

        if (finalBids.length > 0) {
            // Accuser 2 accuses Bidder A of false bid
            await mainContract.connect(accuser2).accuseBidderMalicious(
                auctionId,
                0, // Bidder A's bid index
                { value: ethers.parseEther("0.1") }
            );
            logger.success(`Accuser 2 (${accuser2.address.substring(0, 10)}...) accused Bidder A of false bid`);

            // Bidder A responds to dispute
            await mainContract.connect(bidderA).respondBidderDispute(
                auctionId,
                0,
                bidABigInt,
                bigIntToBytes(bidARandom)
            );
            logger.success(`Bidder A responded to dispute accusation`);

            // Check Bidder A's deposit
            const bidderABondAfter = await mainContract.getParticipationBond(auctionId, bidderA.address);
            logger.info(`Bidder A deposit balance: ${ethers.formatEther(bidderABondAfter)} ETH`);
        }

        // 3.3 Case 3: Accuse challenger of false challenge
        logger.action("Bidder B", "Accusing challenger of false challenge");
        
        const challengeCount = await mainContract.auctionChallengesLength(auctionId);
        logger.info(`Total challenges count: ${challengeCount}`);

        if (challengeCount > 0) {
            const challengeIndex = 0; // First challenge
            
            // Bidder B accuses challenger of false challenge
            await mainContract.connect(bidderB).accuseChallengerMalicious(
                auctionId,
                challengeIndex,
                { value: ethers.parseEther("0.1") }
            );
            logger.success(`Bidder B accused challenger of false challenge`);

            // Wait for response timeout
            logger.action("System", "Waiting for dispute response timeout");
            await ethers.provider.send("evm_increaseTime", [10 * 60 + 1]); // 10 min response time + 1 sec
            await ethers.provider.send("evm_mine");

            // Finalize dispute
            await mainContract.connect(accuser1).finalizeChallengerDispute(auctionId, challengeIndex);
            logger.success("Challenger dispute finalized due to timeout");
        }

        // ==================== Phase 4: Deposit Refunds ====================
        logger.stage("Phase 4: Deposit Refunds");
        logger.separator();

        // 4.1 Wait for dispute period to end
        logger.action("System", "Waiting for dispute period to end");
        const settlementTime = await mainContract.getSettlementTimestamp(auctionId);
        const disputePeriod = 30 * 60; // 30 minutes

        await ethers.provider.send("evm_increaseTime", [disputePeriod + 1]);
        await ethers.provider.send("evm_mine");
        logger.success("Dispute period ended");

        // 4.2 Participants claim deposits
        logger.action("System", "Participants claiming deposits");


        // Participant list
        const participants = [
            { address: seller.address, name: "Seller" },
            { address: bidderA.address, name: "Bidder A" },
            { address: bidderB.address, name: "Bidder B" },
            { address: challenger.address, name: "Challenger" }
        ];

        logger.info("Refunding deposits:");
        for (const participant of participants) {
            const bondBefore = await mainContract.getParticipationBond(auctionId, participant.address);
            if (bondBefore > 0n) {
                logger.info(`${participant.name} deposit: ${ethers.formatEther(bondBefore)} ETH`);
                
                try {
                    await mainContract.connect(await ethers.getSigner(participant.address)).claimParticipationBond(
                        auctionId
                    );
                    logger.success(`Refund successful`);
                } catch (error) {
                    logger.error(`Refund failed: ${error.message}`);
                }
            } else {
                logger.info(`${participant.name}: No deposit to refund`);
            }
        }

        // ==================== Phase 5: Final State Verification ====================
        logger.stage("Phase 5: Final State Verification");
        logger.separator();

        const auctionSettled = await mainContract.isAuctionSettled(auctionId);
        const auctionFailed = await mainContract.isAuctionFailed(auctionId);
        const auctionWinner = await mainContract.getAuctionWinner(auctionId);

        logger.info("Auction final state:");
        logger.info(`Auction settled: ${auctionSettled ? "Yes" : "No"}`);
        logger.info(`Auction failed: ${auctionFailed ? "Yes" : "No"}`);
        logger.info(`Auction winner: ${auctionWinner}`);

        logger.info("Participants final deposit status:");
        const allParticipants = [seller, bidderA, bidderB, challenger, accuser1, accuser2];
        
        for (let i = 0; i < allParticipants.length; i++) {
            const bond = await mainContract.getParticipationBond(auctionId, allParticipants[i].address);
            const shortAddress = allParticipants[i].address.substring(0, 10) + "...";
            logger.info(`${shortAddress}: ${ethers.formatEther(bond)} ETH`);
        }

        logger.success("Test complete: Full dispute scenario test passed!");
        logger.separator();
    });

    /**
     * Test malicious seller case
     * Scenario: Seller provides incorrect reserve price and random number
     */
    it("Should handle malicious seller case", async () => {
        logger.stage("Malicious Seller Case Test");
        logger.info("Scenario: Seller provides incorrect reserve price and random number");

        // 1. Normal auction process
        logger.stage("1. Normal Auction Process");
        
        // Bidder bids
        const bidValue = "2.5";
        const bidBigInt = BigInt(ethers.parseEther(bidValue));
        const bidRandom = generateRandomBigIntInRange(
            bidderAKeys.publicKey.n / RANDOM_RANGE_DIVISOR - 1n
        );

        const eps = {
            c1: bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidBigInt * bidRandom,
                bidderAKeys.publicKey._n2
            )),
            c2: bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidRandom,
                bidderAKeys.publicKey._n2
            ))
        };

        const commitment = ethers.solidityPackedKeccak256(
            ["bytes", "bytes"],
            [bigIntToBytes(bidBigInt), bigIntToBytes(bidRandom)]
        );

        await mainContract.connect(bidderA).claimBid(
            auctionId,
            {
                g: bigIntToBytes(bidderAKeys.publicKey.g),
                n: bigIntToBytes(bidderAKeys.publicKey.n)
            },
            bigIntToBytes(modPow(
                bidderAKeys.publicKey.g,
                bidderAKeys.privateKey.lambda,
                bidderAKeys.publicKey._n2
            )),
            eps,
            commitment,
            { value: ethers.parseEther("0.1") }
        );
        logger.success(`Bidder A bid ${bidValue} ETH`);

        // 2. Wait for auction end and settle
        logger.stage("2. Auction Settlement");
        await ethers.provider.send("evm_increaseTime", [3600 + 600]);
        await ethers.provider.send("evm_mine");

        await mainContract.connect(seller).settleAuction(auctionId);
        logger.success("Auction settled");

        // 3. Accuse seller of false reserve price
        logger.stage("3. Accuse Seller of False Reserve Price");
        await mainContract.connect(accuser1).accuseSellerMalicious(auctionId, {
            value: ethers.parseEther("0.1")
        });
        logger.success(`Accuser accused seller of false reserve price`);

        // 4. Seller provides incorrect reserve price and random number
        logger.stage("4. Seller Provides Incorrect Information");
        const falseReservePrice = sellerReserveBigInt + 1n; // Incorrect reserve price
        const falseRandom = sellerRandom + 1n; // Incorrect random number

        await mainContract.connect(seller).respondSellerDispute(
            auctionId,
            falseReservePrice,
            bigIntToBytes(falseRandom)
        );
        logger.info(`Seller provided incorrect information:`);
        logger.info(`Reserve price: ${ethers.formatEther(falseReservePrice)} ETH (expected: 2.5 ETH)`);
        logger.info(`Random number: modified`);

        // 5. Verify dispute result
        logger.stage("5. Verify Dispute Result");
        await ethers.provider.send("evm_increaseTime", [1]);
        await ethers.provider.send("evm_mine");

        const sellerDisputeInfo = await mainContract.getSellerDisputeInfo(auctionId);
        logger.info(`Dispute result: ${sellerDisputeInfo.guilty ? "Seller guilty" : "Seller not guilty"}`);
        
        if (sellerDisputeInfo.guilty) {
            logger.success("Test passed: Malicious seller correctly identified");
        } else {
            logger.error("Test failed: Malicious seller not identified");
        }

        logger.success("Malicious seller case test completed!");
        logger.separator();
    });
});