// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Paillier Homomorphic Encryption Auction System Data Structures
 * @notice Defines all data structures required for the privacy-preserving auction contract
 */

// ==================== Encryption Related Structures ====================

/**
 * @notice Paillier public key structure
 * @dev Public key parameters for the Paillier homomorphic encryption system
 * @param g Generator
 * @param n Modulus, product of two large prime numbers
 */
struct PublicKeys {
    bytes g;
    bytes n;
}

/**
 * @notice Encryption parameters structure
 * @dev Used to store Paillier encryption results
 * @param c1 Encrypted value 1, represents the encrypted bid price
 * @param c2 Encrypted value 2, auxiliary encrypted value for verification
 */
struct EncryptParameters {
    bytes c1;
    bytes c2;
}

// ==================== Auction Related Structures ====================

/**
 * @notice Auction parameters structure (provided when creating an auction)
 * @dev Auction configuration parameters provided by the auction creator
 * @param info Auction description
 * @param startPrice Starting price
 * @param duration Auction duration (in seconds)
 * @param length Maximum capacity of bid cache
 * @param pks Seller's public key, used to verify encryption results
 * @param verifyParameters Verification parameters, used for subsequent bid verification
 * @param eps Encryption parameters, containing the encrypted starting price
 * @param commitment Commitment value, ensuring subsequent data consistency
 */
struct AuctionParams {
    string info;
    uint256 startPrice;
    uint256 duration;
    uint256 length;
    PublicKeys pks;
    bytes verifyParameters;
    EncryptParameters eps;
    bytes commitment;
}

/**
 * @notice Auction details structure
 * @dev Stores complete auction information
 * @param seller Seller address
 * @param info Auction description
 * @param startPrice Starting price
 * @param duration Auction duration (in seconds)
 * @param length Maximum capacity of bid cache
 * @param pks Seller's public key
 * @param verifyParameters Verification parameters
 * @param eps Encryption parameters
 * @param commitment Commitment value
 * @param startTime Auction start timestamp
 * @param isActive Whether the auction is active
 */
struct Auction {
    address seller;
    string info;
    uint256 startPrice;
    uint256 duration;
    uint256 length;
    PublicKeys pks;
    bytes verifyParameters;
    EncryptParameters eps;
    bytes commitment;
    uint256 startTime;
    bool isActive;
}

/**
 * @notice Auction information summary structure
 * @dev Public auction information, used for frontend display
 * @param seller Seller address
 * @param info Auction description
 * @param startPrice Starting price
 * @param duration Auction duration (in seconds)
 * @param isActive Whether the auction is active
 */
struct AuctionInfo {
    address seller;
    string info;
    uint256 startPrice;
    uint256 duration;
    bool isActive;
}

// ==================== Bid Related Structures ====================

/**
 * @notice Bid claim structure
 * @dev Bid claim submitted by a buyer, containing the encrypted bid price
 * @param bidder Bidder address
 * @param buyerPks Buyer's public key, used for subsequent challenge verification
 * @param verifyParameters Verification parameters, used to prove bid validity
 * @param eps Encryption parameters, containing the encrypted bid price
 * @param commitment Commitment value, ensuring subsequent data consistency
 * @param timestamp Bid submission timestamp
 * @param isValid Marks whether the bid is valid (may be invalidated by challenges)
 */
struct BidClaim {
    address bidder;
    PublicKeys buyerPks;
    bytes verifyParameters;
    EncryptParameters eps;
    bytes commitment;
    uint256 timestamp;
    bool isValid;
}

// ==================== Challenge Related Structures ====================

/**
 * @notice Bid challenge structure
 * @dev Challenge by other participants against a bid claim
 * @param challenger Challenger address
 * @param bidClaimIndex Index of the challenged bid claim
 * @param challengeParameters Challenge parameters, containing encrypted challenge information
 * @param commitment Commitment value, ensuring subsequent data consistency
 * @param timestamp Challenge initiation timestamp
 * @param isResolved Marks whether the challenge has been resolved
 * @param isSuccessful Marks whether the challenge was successful
 */
struct BidChallenge {
    address challenger;
    uint256 bidClaimIndex;
    bytes challengeParameters;
    bytes commitment;
    uint256 timestamp;
    bool isResolved;
    bool isSuccessful;
}

/**
 * @notice Challenge response structure
 * @dev Response by the challenged party to a challenge
 * @param bidClaimIndex Index of the challenged bid
 * @param challengeIndex Corresponding challenge index
 * @param m Response message, containing proof information
 * @param r Response result: 1 indicates success, 0 or other indicates failure
 * @param responder Responder address
 * @param timestamp Response timestamp
 * @param isValid Marks whether the response is valid
 */
struct ChallengeResponse {
    uint256 bidClaimIndex;
    uint256 challengeIndex;
    bytes m;
    int256 r;
    address responder;
    uint256 timestamp;
    bool isValid;
}

// ==================== Settlement Related Structures ====================

/**
 * @notice Settlement stage state structure
 * @dev Tracks the state of the auction settlement phase
 * @param inSettlementChallenge Whether in settlement challenge phase
 * @param finalWinner Final winner address
 * @param settlementCompleted Whether settlement is completed
 * @param finalChallengeTimestamp Final challenge timestamp
 * @param challenger Challenger address
 * @param challengedBidder Challenged bidder address
 * @param challengedBidIndex Index of the challenged bid
 * @param challengeInitiated Whether challenge has been initiated
 * @param challengeResponded Whether challenge has been responded
 */
struct SettlementStage {
    bool inSettlementChallenge;
    address finalWinner;
    bool settlementCompleted;
    uint256 finalChallengeTimestamp;
    address challenger;
    address challengedBidder;
    uint256 challengedBidIndex;
    bool challengeInitiated;
    bool challengeResponded;
}

/**
 * @notice Price reveal parameters structure
 * @dev Parameters required to reveal the encrypted price in the final phase
 * @param price Actual price (plaintext)
 * @param randomness Randomness, used to verify correctness of encryption
 * @param lambda Paillier private key parameter ¦Ë
 * @param mu Paillier private key parameter ¦Ì
 */
struct RevealParams {
    uint256 price;
    bytes randomness;
    bytes lambda;
    bytes mu;
}

/**
 * @dev Reserve challenge data structure
 * @param challenger Challenger address (winning bidder)
 * @param challengeParameters Challenge parameters
 * @param commitment Commitment value
 * @param timestamp Challenge initiation timestamp
 * @param isResolved Whether resolved
 * @param isSuccessful Whether challenge was successful
 */
struct ReserveChallenge {
    address challenger;
    bytes challengeParameters;
    bytes commitment;
    uint256 timestamp;
    bool isResolved;
    bool isSuccessful;
}