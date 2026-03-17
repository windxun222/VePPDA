// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./GlobalsStruct.sol";
import "./VePPDA_Auction.sol";

/**
 * @title VePPDA_Settlement
 * @dev Auction settlement contract that handles the post-auction settlement process, including:
 *       1. Final auction settlement
 *       2. Reserve price challenge mechanism
 *       3. Final bid challenge mechanism
 *       4. Timeout handling and result determination
 */
contract VePPDA_Settlement {
    // ==================== State Variables ====================

    // Reserve challenge mapping (auction ID => challenge data)
    mapping(uint256 => ReserveChallenge) public reserveChallenges;

    // Whether a reserve challenge has been initiated for an auction
    mapping(uint256 => bool) public isReserveChallenged;

    // Whether a reserve challenge response has been submitted
    mapping(uint256 => bool) public isReserveResponseSubmitted;

    // Participation bond records (mapping not actually used for refunds, retaining original logic)
    mapping(uint256 => mapping(address => uint256)) public participationBonds;

    // Auction contract instance
    VePPDA_Auction public auctionContract;

    // Auction winner mapping (auction ID => winner address)
    mapping(uint256 => address) public auctionWinner;

    // Whether auction settlement is completed
    mapping(uint256 => bool) public auctionSettled;

    // Whether auction failed (no valid bids)
    mapping(uint256 => bool) public auctionFailed;

    // Auction settlement timestamp
    mapping(uint256 => uint256) public settlementTimestamp;

    // Auction settlement stage state
    mapping(uint256 => SettlementStage) public auctionSettlementStage;

    // ==================== Constants ====================

    // Challenge response time window (1 minute)
    uint256 public constant CHALLENGE_RESPONSE_TIME = 1 minutes;

    // Final challenge timeout (3 minutes)
    uint256 public constant FINAL_CHALLENGE_TIMEOUT = 3 minutes;

    // Participation bond amount (0.1 ETH)
    uint256 public constant PARTICIPATION_BOND = 0.1 ether;

    // ==================== Error Definitions ====================

    error AuctionAlreadySettled();
    error AuctionNotEnded();
    error InvalidSettlementState();
    error BidAlreadyChallenged();
    error OnlyValidBidderCanChallengeInSettlement();
    error BidNotFound();
    error InvalidParameters();
    error OnlyChallengedBidderCanRespond();
    error ChallengeNotActive();
    error SettlementChallengeTimeout();
    error OnlyOneBidderCanChallenge();
    error BidderCannotChallengeSelf();
    error Unauthorized();
    error ChallengeAlreadyResponded();
    error AuctionNotActive();
    error AuctionAlreadyEnded();
    error IncorrectBondAmount();
    error FallbackNotAllowed();

    // ==================== Events ====================

    // Auction settled event
    event AuctionSettled(uint256 indexed auctionId, address indexed winner);

    // Auction failed event
    event AuctionFailed(uint256 indexed auctionId);

    // Final challenge initiated event
    event FinalChallengeInitiated(
        uint256 indexed auctionId,
        address indexed challenger,
        address indexed challengedBidder,
        bytes challengeParameters,
        bytes commitment
    );

    // Final challenge responded event
    event FinalChallengeResponded(
        uint256 indexed auctionId,
        address indexed responder,
        bytes m,
        int256 r
    );

    // Final winner determined event
    event FinalWinnerDetermined(
        uint256 indexed auctionId,
        address indexed winner,
        bool challengeSuccessful
    );

    // Reserve challenge initiated event
    event ReserveChallenged(
        uint256 indexed auctionId,
        address indexed challenger,
        bytes challengeParameters,
        bytes commitment,
        uint256 timestamp
    );

    // Reserve challenge responded event
    event ReserveChallengeResponded(
        uint256 indexed auctionId,
        address indexed responder,
        int256 r,
        uint256 timestamp
    );

    // Reserve challenge result event
    event ReserveChallengeResult(
        uint256 indexed auctionId,
        bool isSuccessful,
        address indexed winner
    );

    // ==================== Constructor ====================

    /**
     * @dev Constructor, initializes the auction contract address
     * @param _auctionContract Address of the auction contract
     */
    constructor(address _auctionContract) {
        auctionContract = VePPDA_Auction(payable(_auctionContract));
    }

    // ==================== Modifiers ====================

    /**
     * @dev Validates the auction ID
     * @param auctionId Auction ID
     */
    modifier onlyValidAuction(uint256 auctionId) {
        if (auctionId == 0 || auctionId > auctionContract.getAuctionCount())
            revert Unauthorized();
        _;
    }

    // ==================== Core Settlement Functions ====================

    /**
     * @dev Auction settlement function
     *      1. Verifies the caller is the seller
     *      2. Checks if the auction is already settled
     *      3. Checks if the auction has ended
     *      4. Retrieves valid bids
     *      5. Determines result based on the number of valid bids:
     *         - 0: auction fails
     *         - 1: direct win
     *         - 2: enters final challenge phase
     * @param auctionId Auction ID
     */
    function settleAuction(
        uint256 auctionId
    ) external onlyValidAuction(auctionId) {

        // Check if auction is already settled
        if (auctionSettled[auctionId]) revert AuctionAlreadySettled();

        // Retrieve auction information and validate state
        Auction memory auction = auctionContract.getAuction(auctionId);
        if (!auction.isActive) revert AuctionNotActive();

        // Verify auction has ended (including challenge response time)
        if (
            block.timestamp <
            auction.startTime + auction.duration + CHALLENGE_RESPONSE_TIME
        ) revert AuctionNotEnded();

        // Get all valid bids
        BidClaim[] memory allBids = auctionContract.getValidAuctionBids(
            auctionId
        );

        // Find valid, unchallenged bids
        address validBidder1 = address(0);
        address validBidder2 = address(0);
        uint256 validIndex1 = 0;
        uint256 validIndex2 = 0;
        uint256 validCount = 0;

        for (uint256 i = 0; i < allBids.length; i++) {
            if (
                allBids[i].isValid &&
                !auctionContract.getisBidClaimChallenged(auctionId, i)
            ) {
                if (validCount == 0) {
                    validBidder1 = allBids[i].bidder;
                    validIndex1 = i;
                } else if (validCount == 1) {
                    validBidder2 = allBids[i].bidder;
                    validIndex2 = i;
                } else {
                    revert InvalidSettlementState();
                }
                validCount++;
            }
        }

        // Mark auction as settled and record timestamp
        auctionSettled[auctionId] = true;
        settlementTimestamp[auctionId] = block.timestamp;

        // Handle different numbers of valid bids
        if (validCount == 0) {
            // No valid bids: auction fails
            auctionFailed[auctionId] = true;
            emit AuctionFailed(auctionId);
        } else if (validCount == 1) {
            // One valid bid: direct win
            auctionWinner[auctionId] = validBidder1;
            emit AuctionSettled(auctionId, validBidder1);
        } else if (validCount == 2) {
            // Two valid bids: enter final challenge phase
            auctionSettlementStage[auctionId] = SettlementStage({
                inSettlementChallenge: true,
                finalWinner: address(0),
                settlementCompleted: false,
                finalChallengeTimestamp: 0,
                challenger: validBidder2,
                challengedBidder: validBidder1,
                challengedBidIndex: validIndex1,
                challengeInitiated: false,
                challengeResponded: false
            });
        }
    }

    // ==================== Reserve Challenge Functions ====================

    /**
     * @dev Initiates a reserve price challenge (only callable by the winner)
     *      The winner can challenge the auction's reserve price, requires a bond.
     * @param auctionId Auction ID
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment value
     * @param sender Caller address
     */
    function challengeReserve(
        uint256 auctionId,
        bytes calldata challengeParameters,
        bytes calldata commitment,
        address sender
    ) external payable onlyValidAuction(auctionId) {
        // Validate auction state
        if (!auctionSettled[auctionId]) revert AuctionAlreadySettled();
        if (auctionFailed[auctionId]) revert InvalidSettlementState();

        // Check if a reserve challenge has already been initiated
        if (isReserveChallenged[auctionId]) revert BidAlreadyChallenged();

        // Verify caller is the current winner
        if (sender != auctionWinner[auctionId]) revert Unauthorized();

        // Validate parameter validity
        if (challengeParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        // Validate bond amount
        if (msg.value != PARTICIPATION_BOND) revert IncorrectBondAmount();

        // Create reserve challenge record
        reserveChallenges[auctionId] = ReserveChallenge({
            challenger: sender,
            challengeParameters: challengeParameters,
            commitment: commitment,
            timestamp: block.timestamp,
            isResolved: false,
            isSuccessful: false
        });

        // Update state
        isReserveChallenged[auctionId] = true;
        participationBonds[auctionId][sender] += msg.value;

        // Emit event
        emit ReserveChallenged(
            auctionId,
            sender,
            challengeParameters,
            commitment,
            block.timestamp
        );
    }

    /**
     * @dev Responds to a reserve challenge
     *      The seller must respond within the time window, otherwise the challenge automatically succeeds.
     * @param auctionId Auction ID
     * @param m Response message
     * @param r Response result (r <= 0 indicates challenge success)
     * @param responder Responder address
     */
    function respondToChallengeReserve(
        uint256 auctionId,
        bytes calldata m,
        int256 r,
        address responder
    ) external onlyValidAuction(auctionId) {
        // Validate challenge state
        if (!isReserveChallenged[auctionId]) revert ChallengeNotActive();
        if (isReserveResponseSubmitted[auctionId])
            revert ChallengeAlreadyResponded();

        // Verify caller is the seller
        address seller = auctionContract.getAuctionSeller(auctionId);
        if (responder != seller) revert Unauthorized();

        // Retrieve challenge record
        ReserveChallenge storage challenge = reserveChallenges[auctionId];

        // Check if timed out
        bool isTimedOut = block.timestamp >
            challenge.timestamp + CHALLENGE_RESPONSE_TIME;

        bool isChallengeSuccessful;
        if (!isTimedOut) {
            // Not timed out: validate parameters and check r value
            if (m.length == 0) revert InvalidParameters();
            isChallengeSuccessful = (r <= 0); // r <= 0 indicates challenge success
        } else {
            // Timed out: challenge automatically succeeds
            isChallengeSuccessful = true;
        }

        // Update challenge state
        challenge.isResolved = true;
        challenge.isSuccessful = isChallengeSuccessful;
        isReserveResponseSubmitted[auctionId] = true;

        // If challenge succeeds, auction fails and winner is cleared
        if (!isChallengeSuccessful) {
            auctionFailed[auctionId] = true;
            auctionWinner[auctionId] = address(0);
        }

        // Emit events
        emit ReserveChallengeResponded(
            auctionId,
            responder,
            r,
            block.timestamp
        );
        emit ReserveChallengeResult(
            auctionId,
            isChallengeSuccessful,
            isChallengeSuccessful ? challenge.challenger : address(0)
        );
    }

    // ==================== Final Challenge Functions ====================

    /**
     * @dev Initiates a final bid challenge (only callable by the challenger)
     *      When there are two valid bids, the second bidder can challenge the first bidder.
     * @param auctionId Auction ID
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment value
     * @param sender Caller address
     */
    function challengeBidFinal(
        uint256 auctionId,
        bytes calldata challengeParameters,
        bytes calldata commitment,
        address sender
    ) external onlyValidAuction(auctionId) {
        // Retrieve settlement stage state
        SettlementStage storage settlement = auctionSettlementStage[auctionId];

        // Validate state
        if (!settlement.inSettlementChallenge) revert InvalidSettlementState();
        if (settlement.challengeInitiated) revert BidAlreadyChallenged();
        if (sender != settlement.challenger)
            revert OnlyValidBidderCanChallengeInSettlement();

        // Validate parameters
        if (challengeParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        // Verify challenged bid exists and is valid
        uint256 challengedIdx = settlement.challengedBidIndex;
        BidClaim[] memory bids = auctionContract.getValidAuctionBids(auctionId);
        if (
            challengedIdx >= bids.length ||
            !bids[challengedIdx].isValid ||
            bids[challengedIdx].bidder == sender
        ) revert BidNotFound();

        // Call the auction contract's final challenge function
        auctionContract.challengeBidFinal(
            auctionId,
            challengedIdx,
            challengeParameters,
            commitment,
            sender
        );

        // Update state
        settlement.challengeInitiated = true;
        settlement.finalChallengeTimestamp = block.timestamp;

        // Emit event
        emit FinalChallengeInitiated(
            auctionId,
            sender,
            settlement.challengedBidder,
            challengeParameters,
            commitment
        );
    }

    /**
     * @dev Responds to a final bid challenge (only callable by the challenged bidder)
     * @param auctionId Auction ID
     * @param m Response message
     * @param r Response result
     * @param sender Caller address
     */
    function respondToChallengeFinal(
        uint256 auctionId,
        bytes calldata m,
        int256 r,
        address sender
    ) external onlyValidAuction(auctionId) {
        // Retrieve settlement stage state
        SettlementStage storage settlement = auctionSettlementStage[auctionId];

        // Validate state
        if (!settlement.inSettlementChallenge) revert InvalidSettlementState();
        if (!settlement.challengeInitiated || settlement.challengeResponded)
            revert ChallengeNotActive();

        // Check if timed out
        if (
            block.timestamp >
            settlement.finalChallengeTimestamp + FINAL_CHALLENGE_TIMEOUT
        ) {
            _handleChallengeTimeout(auctionId);
            return;
        }

        // Verify caller is the challenged bidder
        if (sender != settlement.challengedBidder)
            revert OnlyChallengedBidderCanRespond();
        if (m.length == 0) revert InvalidParameters();

        // Call the auction contract's final challenge response function
        uint256 challengedIdx = settlement.challengedBidIndex;
        auctionContract.respondToChallengeFinal(
            auctionId,
            challengedIdx,
            m,
            r,
            sender
        );

        // Update state
        settlement.challengeResponded = true;

        // Emit event
        emit FinalChallengeResponded(auctionId, sender, m, r);

        // Check challenge result
        _checkChallengeResult(auctionId, challengedIdx);
    }

    /**
     * @dev Finalizes challenge result by timeout
     *      If the challenged bidder does not respond within the specified time, the challenger automatically wins.
     * @param auctionId Auction ID
     */
    function finalizeChallengeByTimeout(
        uint256 auctionId
    ) external onlyValidAuction(auctionId) {
        // Retrieve settlement stage state
        SettlementStage storage settlement = auctionSettlementStage[auctionId];

        // Validate state
        if (!settlement.inSettlementChallenge) revert InvalidSettlementState();
        if (!settlement.challengeInitiated || settlement.challengeResponded)
            revert ChallengeNotActive();

        // Verify timeout has occurred
        if (
            block.timestamp <=
            settlement.finalChallengeTimestamp + FINAL_CHALLENGE_TIMEOUT
        ) revert SettlementChallengeTimeout();

        // Handle timeout
        _handleChallengeTimeout(auctionId);
    }

    // ==================== Internal Functions ====================

    /**
     * @dev Handles challenge timeout (internal function)
     *      Challenger automatically wins.
     * @param auctionId Auction ID
     */
    function _handleChallengeTimeout(uint256 auctionId) internal {
        // Retrieve settlement stage state
        SettlementStage storage settlement = auctionSettlementStage[auctionId];

        // Challenger wins
        address winner = settlement.challenger;

        // Update state
        settlement.finalWinner = winner;
        settlement.settlementCompleted = true;
        settlement.inSettlementChallenge = false;
        auctionWinner[auctionId] = winner;

        // Emit events
        emit FinalWinnerDetermined(auctionId, winner, true);
        emit AuctionSettled(auctionId, winner);
    }

    /**
     * @dev Checks challenge result (internal function)
     *      Determines the final winner based on the challenge result in the auction contract.
     * @param auctionId Auction ID
     * @param challengedBidIndex Index of the challenged bid
     */
    function _checkChallengeResult(
        uint256 auctionId,
        uint256 challengedBidIndex
    ) internal {
        // Retrieve challenge index
        uint256 challengeIndex = getChallengeIndexForBid(
            auctionId,
            challengedBidIndex
        );

        // Get challenge result
        bool isChallengeSuccessful = auctionContract.getChallengeResult(
            auctionId,
            challengeIndex
        );

        // Retrieve settlement stage state
        SettlementStage storage settlement = auctionSettlementStage[auctionId];

        // Determine winner based on challenge result
        // isChallengeSuccessful == true means challenge succeeded, challenged bid is invalid, challenger wins
        // isChallengeSuccessful == false means challenge failed, challenged bid is valid, challenged bidder wins
        address winner = isChallengeSuccessful
            ? settlement.challengedBidder // Challenge succeeded: challenged bidder wins
            : settlement.challenger; // Challenge failed: challenger wins

        // Update state
        settlement.finalWinner = winner;
        settlement.settlementCompleted = true;
        settlement.inSettlementChallenge = false;
        auctionWinner[auctionId] = winner;

        // Emit events
        emit FinalWinnerDetermined(auctionId, winner, !isChallengeSuccessful);
        emit AuctionSettled(auctionId, winner);
    }

    /**
     * @dev Gets the challenge index for a given bid (internal function)
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @return Challenge index
     */
    function getChallengeIndexForBid(
        uint256 auctionId,
        uint256 bidClaimIndex
    ) internal view returns (uint256) {
        // Get challenge index from auction contract
        uint256 challengeIndex = auctionContract.bidClaimToChallengeIndex(
            auctionId,
            bidClaimIndex
        );

        // Validate challenge index
        uint256 challengeCount = auctionContract.auctionChallengesLength(
            auctionId
        );
        if (challengeIndex >= challengeCount) revert ChallengeNotActive();

        // Verify challenge's bid index matches
        BidChallenge memory challenge = auctionContract.getChallenge(
            auctionId,
            challengeIndex
        );
        if (challenge.bidClaimIndex != bidClaimIndex)
            revert ChallengeNotActive();

        return challengeIndex;
    }

    // ==================== View Functions ====================

    /**
     * @dev Gets the auction winner
     * @param auctionId Auction ID
     * @return Winner address
     */
    function getAuctionWinner(
        uint256 auctionId
    ) external view returns (address) {
        return auctionWinner[auctionId];
    }

    /**
     * @dev Checks if an auction is settled
     * @param auctionId Auction ID
     * @return Whether settled
     */
    function isAuctionSettled(uint256 auctionId) external view returns (bool) {
        return auctionSettled[auctionId];
    }

    /**
     * @dev Checks if an auction failed
     * @param auctionId Auction ID
     * @return Whether failed
     */
    function isAuctionFailed(uint256 auctionId) external view returns (bool) {
        return auctionFailed[auctionId];
    }

    /**
     * @dev Gets the settlement timestamp
     * @param auctionId Auction ID
     * @return Settlement timestamp
     */
    function getSettlementTimestamp(
        uint256 auctionId
    ) external view returns (uint256) {
        return settlementTimestamp[auctionId];
    }

    /**
     * @dev Gets the settlement stage state
     * @param auctionId Auction ID
     * @return Settlement stage state structure
     */
    function getSettlementStage(
        uint256 auctionId
    ) external view returns (SettlementStage memory) {
        return auctionSettlementStage[auctionId];
    }

    /**
     * @dev Checks if the final challenge has timed out
     * @param auctionId Auction ID
     * @return Whether timed out
     */
    function isFinalChallengeTimeout(
        uint256 auctionId
    ) external view returns (bool) {
        SettlementStage storage settlement = auctionSettlementStage[auctionId];
        if (!settlement.inSettlementChallenge || !settlement.challengeInitiated)
            return false;

        return
            block.timestamp >
            settlement.finalChallengeTimestamp + FINAL_CHALLENGE_TIMEOUT;
    }

    /**
     * @dev Gets reserve challenge information
     * @param auctionId Auction ID
     * @return Reserve challenge structure
     */
    function getReserveChallenge(
        uint256 auctionId
    ) external view returns (ReserveChallenge memory) {
        return reserveChallenges[auctionId];
    }

    /**
     * @dev Checks if a reserve challenge is active
     * @param auctionId Auction ID
     * @return Whether active (initiated but not responded)
     */
    function isReserveChallengeActive(
        uint256 auctionId
    ) external view returns (bool) {
        return
            isReserveChallenged[auctionId] &&
            !isReserveResponseSubmitted[auctionId];
    }

    // ==================== Security Fallback ====================

    /**
     * @dev Prevents fallback calls
     */
    fallback() external payable {
        revert FallbackNotAllowed();
    }

    /**
     * @dev Allows receiving Ether (no restrictions)
     */
    receive() external payable {}
}