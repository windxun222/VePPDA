// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import dependent contracts
import "./GlobalsStruct.sol";
import "./Verifier.sol";
import "./VePPDA_Auction.sol";
import "./VePPDA_Settlement.sol";

/**
 * @title VePPDA_Dispute
 * @dev Handles three types of disputes in the auction system:
 *       1. Seller malicious reserve price dispute
 *       2. Bidder malicious bid claim dispute  
 *       3. Bidder malicious challenge dispute
 * @notice This contract manages dispute accusations, responses, and adjudication processes, incorporating a bond mechanism.
 */
contract VePPDA_Dispute {
    
    // ==================== External Contract References ====================
    VePPDA_Auction public auctionContract;      // Auction contract
    VePPDA_Settlement public settlementContract; // Settlement contract

    // ==================== State Variables ====================
    
    // --- Seller dispute mappings (Case 1) ---
    mapping(uint256 => address) public sellerDisputeAccuser;   // Accuser address
    mapping(uint256 => uint256) public sellerDisputeStart;     // Accusation start time
    mapping(uint256 => uint256) public sellerDisputeBond;      // Dispute bond
    mapping(uint256 => bool) public sellerDisputeResponded;    // Whether responded
    mapping(uint256 => bool) public sellerGuilty;              // Whether found guilty

    // --- Buyer malicious bid claim dispute mappings (Case 2) ---
    mapping(uint256 => mapping(uint256 => address)) public bidDisputeAccuser;   // Accuser by bid index
    mapping(uint256 => mapping(uint256 => uint256)) public bidDisputeStart;     // Accusation start time
    mapping(uint256 => mapping(uint256 => uint256)) public bidDisputeBond;      // Dispute bond
    mapping(uint256 => mapping(uint256 => bool)) public bidDisputeResponded;    // Whether responded
    mapping(uint256 => mapping(uint256 => bool)) public bidGuilty;              // Whether found guilty

    // --- Buyer malicious challenge dispute mappings (Case 3) ---
    mapping(uint256 => mapping(uint256 => address)) public challengeDisputeAccuser;   // Accuser by challenge index
    mapping(uint256 => mapping(uint256 => uint256)) public challengeDisputeStart;     // Accusation start time
    mapping(uint256 => mapping(uint256 => uint256)) public challengeDisputeBond;      // Dispute bond
    mapping(uint256 => mapping(uint256 => bool)) public challengeDisputeResponded;    // Whether responded
    mapping(uint256 => mapping(uint256 => bool)) public challengeGuilty;              // Whether found guilty

    // ==================== Configuration Constants ====================
    uint256 public constant DISPUTE_RESPONSE_TIME = 10 minutes; // Dispute response deadline
    uint256 public constant DISPUTE_PERIOD = 30 minutes;        // Total dispute period
    uint256 public constant DISPUTE_BOND = 0.1 ether;           // Dispute bond amount

    // ==================== Error Definitions ====================
    error DisputePeriodEnded();       // Dispute period has ended
    error DisputeAlreadyExists();     // Dispute already exists
    error NotAuthorized();           // Unauthorized operation
    error ResponseTimeout();         // Response timeout
    error AlreadyResponded();        // Dispute already responded to
    error AuctionNotSettled();       // Auction not settled

    // Additional custom errors
    error IncorrectDisputeBond();    // Incorrect bond amount
    error TransferFailed();          // Transfer failed
    error FallbackNotAllowed();      // Fallback not allowed

    // ==================== Event Definitions ====================
    event SellerAccused(uint256 indexed auctionId, address indexed accuser);
    event BidderAccused(uint256 indexed auctionId, uint256 indexed bidIndex, address indexed accuser);
    event ChallengerAccused(uint256 indexed auctionId, uint256 indexed challengeIndex, address indexed accuser);
    event DisputeResponded(uint256 indexed auctionId, address indexed accused, bool guilty);
    event DisputeResolved(uint256 indexed auctionId, address indexed winner, uint256 slashedAmount);
    event BondRefunded(uint256 indexed auctionId, address indexed participant, uint256 amount);

    // ==================== Constructor ====================
    /**
     * @dev Initializes the contract by setting dependent contract addresses
     * @param _auctionContract Address of the auction contract
     * @param _settlementContract Address of the settlement contract
     */
    constructor(address _auctionContract, address _settlementContract) {
        auctionContract = VePPDA_Auction(payable(_auctionContract));
        settlementContract = VePPDA_Settlement(payable(_settlementContract));
    }

    // ==================== Modifiers ====================
    
    /**
     * @dev Ensures the auction has been settled or failed
     * @param auctionId Auction ID
     */
    modifier onlySettledAuction(uint256 auctionId) {
        bool settled = settlementContract.isAuctionSettled(auctionId);
        bool failed = settlementContract.isAuctionFailed(auctionId);
        require(settled || failed, "Auction not settled");
        _;
    }

    /**
     * @dev Ensures operation is within the dispute period
     * @param auctionId Auction ID
     */
    modifier withinDisputePeriod(uint256 auctionId) {
        uint256 settlementTime = settlementContract.getSettlementTimestamp(auctionId);
        require(block.timestamp <= settlementTime + DISPUTE_PERIOD, "Dispute period ended");
        _;
    }

    // ==================== Dispute Handling Functions ====================
    
    // ---------- Case 1: Seller Malicious Reserve Price Dispute ----------
    
    /**
     * @dev Accuses the seller of a malicious reserve price
     * @param auctionId Auction ID
     * @param caller Accuser address
     * @notice Requires payment of DISPUTE_BOND as a bond
     */
    function accuseSellerMalicious(
        uint256 auctionId,
        address caller
    )
        external
        payable
        onlySettledAuction(auctionId)
        withinDisputePeriod(auctionId)
    {
        if (msg.value != DISPUTE_BOND) revert IncorrectDisputeBond();
        if (sellerDisputeAccuser[auctionId] != address(0)) revert DisputeAlreadyExists();

        sellerDisputeAccuser[auctionId] = caller;
        sellerDisputeStart[auctionId] = block.timestamp;
        sellerDisputeBond[auctionId] = msg.value;

        emit SellerAccused(auctionId, caller);
    }

    /**
     * @dev Seller responds to the dispute accusation
     * @param auctionId Auction ID
     * @param revealedReservePrice Revealed reserve price
     * @param revealedRandomness Revealed randomness
     * @param caller Responder address (must be the seller)
     */
    function respondSellerDispute(
        uint256 auctionId,
        uint256 revealedReservePrice,
        bytes memory revealedRandomness,
        address caller
    ) external {
        address seller = auctionContract.getAuctionSeller(auctionId);
        if (caller != seller) revert NotAuthorized();
        if (sellerDisputeAccuser[auctionId] == address(0)) revert DisputeAlreadyExists();
        if (sellerDisputeResponded[auctionId]) revert AlreadyResponded();
        if (block.timestamp > sellerDisputeStart[auctionId] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        Auction memory auction = auctionContract.getAuction(auctionId);

        // Verify if the seller is honest: check hash commitment, Paillier encryption, and randomness range
        bool honest = Verifier.verifyHashCommitment(
            bytes32(auction.commitment),
            revealedReservePrice,
            revealedRandomness
        ) &&
        Verifier.verifyPaillierEncryption(
            auction.pks.g,
            auction.pks.n,
            auction.eps.c1,
            auction.eps.c2,
            revealedReservePrice,
            revealedRandomness
        ) &&
        Verifier.isRandomnessInSafeRange(auction.pks.n, revealedRandomness);

        sellerGuilty[auctionId] = !honest;
        sellerDisputeResponded[auctionId] = true;
        _resolveSellerDispute(auctionId);
    }

    /**
     * @dev Finalizes the seller dispute (automatic processing on timeout)
     * @param auctionId Auction ID
     */
    function finalizeSellerDispute(uint256 auctionId) external {
        if (sellerDisputeAccuser[auctionId] == address(0)) revert DisputeAlreadyExists();
        if (block.timestamp <= sellerDisputeStart[auctionId] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        // If no response by deadline, consider guilty
        sellerGuilty[auctionId] = !sellerDisputeResponded[auctionId];
        _resolveSellerDispute(auctionId);
    }

    /**
     * @dev Internal function: resolves the seller dispute and handles funds
     * @param auctionId Auction ID
     */
    function _resolveSellerDispute(uint256 auctionId) internal {
        address accuser = sellerDisputeAccuser[auctionId];
        address seller = auctionContract.getAuctionSeller(auctionId);
        uint256 accuserBond = sellerDisputeBond[auctionId];
        uint256 sellerBond = auctionContract.getParticipationBond(auctionId, seller);

        if (sellerGuilty[auctionId]) {
            // Seller guilty: accuser gets their bond back, seller's participation bond is slashed
            _safeTransfer(payable(accuser), accuserBond);
            auctionContract.updateParticipationBond(auctionId, seller, 0);

            emit DisputeResolved(auctionId, accuser, accuserBond + sellerBond);
        } else {
            // Seller not guilty: seller receives the accuser's bond
            _safeTransfer(payable(seller), accuserBond);
            emit DisputeResolved(auctionId, seller, accuserBond);
        }

        // Clean up state
        sellerDisputeAccuser[auctionId] = address(0);
        sellerDisputeBond[auctionId] = 0;
        emit DisputeResponded(auctionId, seller, sellerGuilty[auctionId]);
    }

    // ---------- Case 2: Buyer Malicious Bid Claim Dispute ----------
    
    /**
     * @dev Accuses a buyer of a malicious bid claim
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param caller Accuser address
     */
    function accuseBidderMalicious(
        uint256 auctionId,
        uint256 bidClaimIndex,
        address caller
    )
        external
        payable
        onlySettledAuction(auctionId)
        withinDisputePeriod(auctionId)
    {
        if (msg.value != DISPUTE_BOND) revert IncorrectDisputeBond();
        if (bidDisputeAccuser[auctionId][bidClaimIndex] != address(0)) revert DisputeAlreadyExists();

        bidDisputeAccuser[auctionId][bidClaimIndex] = caller;
        bidDisputeStart[auctionId][bidClaimIndex] = block.timestamp;
        bidDisputeBond[auctionId][bidClaimIndex] = msg.value;

        emit BidderAccused(auctionId, bidClaimIndex, caller);
    }

    /**
     * @dev Buyer responds to the bid dispute accusation
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param revealedBidPrice Revealed bid price
     * @param revealedRandomness Revealed randomness
     * @param caller Responder address (must be the accused buyer)
     */
    function respondBidderDispute(
        uint256 auctionId,
        uint256 bidClaimIndex,
        uint256 revealedBidPrice,
        bytes memory revealedRandomness,
        address caller
    ) external {
        BidClaim[] memory bids = auctionContract.getValidAuctionBids(auctionId);
        if (bidClaimIndex >= bids.length) revert NotAuthorized();
        BidClaim memory bid = bids[bidClaimIndex];

        if (caller != bid.bidder) revert NotAuthorized();
        if (bidDisputeAccuser[auctionId][bidClaimIndex] == address(0)) revert DisputeAlreadyExists();
        if (bidDisputeResponded[auctionId][bidClaimIndex]) revert AlreadyResponded();
        if (block.timestamp > bidDisputeStart[auctionId][bidClaimIndex] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        // Verify if the buyer's bid is honest
        bool honest = Verifier.verifyHashCommitment(
            bytes32(bid.commitment),
            revealedBidPrice,
            revealedRandomness
        ) &&
        Verifier.verifyPaillierEncryption(
            bid.buyerPks.g,
            bid.buyerPks.n,
            bid.eps.c1,
            bid.eps.c2,
            revealedBidPrice,
            revealedRandomness
        ) &&
        Verifier.isRandomnessInSafeRange(bid.buyerPks.n, revealedRandomness);

        bidGuilty[auctionId][bidClaimIndex] = !honest;
        bidDisputeResponded[auctionId][bidClaimIndex] = true;
        _resolveBidderDispute(auctionId, bidClaimIndex);
    }

    /**
     * @dev Finalizes the buyer bid dispute (automatic processing on timeout)
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     */
    function finalizeBidderDispute(uint256 auctionId, uint256 bidClaimIndex) external {
        if (bidDisputeAccuser[auctionId][bidClaimIndex] == address(0)) revert DisputeAlreadyExists();
        if (block.timestamp <= bidDisputeStart[auctionId][bidClaimIndex] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        bidGuilty[auctionId][bidClaimIndex] = !bidDisputeResponded[auctionId][bidClaimIndex];
        _resolveBidderDispute(auctionId, bidClaimIndex);
    }

    /**
     * @dev Internal function: resolves the buyer bid dispute and handles funds
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     */
    function _resolveBidderDispute(uint256 auctionId, uint256 bidClaimIndex) internal {
        address accuser = bidDisputeAccuser[auctionId][bidClaimIndex];
        BidClaim[] memory bids = auctionContract.getValidAuctionBids(auctionId);
        if (bidClaimIndex >= bids.length) revert NotAuthorized();
        address accused = bids[bidClaimIndex].bidder;

        uint256 accuserBond = bidDisputeBond[auctionId][bidClaimIndex];
        uint256 accusedBond = auctionContract.getParticipationBond(auctionId, accused);

        if (bidGuilty[auctionId][bidClaimIndex]) {
            // Buyer guilty: accuser gets their bond back, buyer's participation bond is slashed
            _safeTransfer(payable(accuser), accuserBond);
            auctionContract.updateParticipationBond(auctionId, accused, 0);

            emit DisputeResolved(auctionId, accuser, accuserBond + accusedBond);
        } else {
            // Buyer not guilty: buyer receives the accuser's bond
            _safeTransfer(payable(accused), accuserBond);
            emit DisputeResolved(auctionId, accused, accuserBond);
        }

        // Clean up state
        bidDisputeAccuser[auctionId][bidClaimIndex] = address(0);
        bidDisputeBond[auctionId][bidClaimIndex] = 0;
        emit DisputeResponded(auctionId, accused, bidGuilty[auctionId][bidClaimIndex]);
    }

    // ---------- Case 3: Buyer Malicious Challenge Dispute ----------
    
    /**
     * @dev Accuses a challenger of a malicious challenge
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     * @param caller Accuser address
     */
    function accuseChallengerMalicious(
        uint256 auctionId,
        uint256 challengeIndex,
        address caller
    )
        external
        payable
        onlySettledAuction(auctionId)
        withinDisputePeriod(auctionId)
    {
        if (msg.value != DISPUTE_BOND) revert IncorrectDisputeBond();
        if (challengeDisputeAccuser[auctionId][challengeIndex] != address(0)) revert DisputeAlreadyExists();

        challengeDisputeAccuser[auctionId][challengeIndex] = caller;
        challengeDisputeStart[auctionId][challengeIndex] = block.timestamp;
        challengeDisputeBond[auctionId][challengeIndex] = msg.value;

        emit ChallengerAccused(auctionId, challengeIndex, caller);
    }

    /**
     * @dev Challenger responds to the dispute accusation
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     * @param revealedChallengerBid Revealed challenger's bid
     * @param revealedChallengeValue Revealed challenge value
     * @param revealedChallengeRandomness Revealed challenge randomness
     * @param caller Responder address (must be the accused challenger)
     */
    function respondChallengerDispute(
        uint256 auctionId,
        uint256 challengeIndex,
        uint256 revealedChallengerBid,
        bytes memory revealedChallengeValue,
        bytes memory revealedChallengeRandomness,
        address caller
    ) external {
        BidChallenge memory challenge = auctionContract.getChallenge(auctionId, challengeIndex);

        if (caller != challenge.challenger) revert NotAuthorized();
        if (challengeDisputeAccuser[auctionId][challengeIndex] == address(0)) revert DisputeAlreadyExists();
        if (challengeDisputeResponded[auctionId][challengeIndex]) revert AlreadyResponded();
        if (block.timestamp > challengeDisputeStart[auctionId][challengeIndex] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        uint256 bidClaimIndex = challenge.bidClaimIndex;
        BidClaim[] memory bids = auctionContract.getValidAuctionBids(auctionId);
        if (bidClaimIndex >= bids.length) revert NotAuthorized();
        BidClaim memory bid = bids[bidClaimIndex];

        Auction memory auction = auctionContract.getAuction(auctionId);

        // Verify if the challenge is honest
        bool isHonest = Verifier.verifyFalseClaimChallenge(
            bid.buyerPks.n,
            bid.eps.c1,
            bid.eps.c2,
            auction.eps.c1,
            revealedChallengerBid,
            revealedChallengeValue,
            revealedChallengeRandomness
        );

        challengeGuilty[auctionId][challengeIndex] = !isHonest;
        challengeDisputeResponded[auctionId][challengeIndex] = true;

        _resolveChallengerDispute(auctionId, challengeIndex);
    }

    /**
     * @dev Finalizes the challenger dispute (automatic processing on timeout)
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     */
    function finalizeChallengerDispute(uint256 auctionId, uint256 challengeIndex) external {
        if (challengeDisputeAccuser[auctionId][challengeIndex] == address(0)) revert DisputeAlreadyExists();
        if (block.timestamp <= challengeDisputeStart[auctionId][challengeIndex] + DISPUTE_RESPONSE_TIME) revert ResponseTimeout();

        challengeGuilty[auctionId][challengeIndex] = !challengeDisputeResponded[auctionId][challengeIndex];
        _resolveChallengerDispute(auctionId, challengeIndex);
    }

    /**
     * @dev Internal function: resolves the challenger dispute and handles funds
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     */
    function _resolveChallengerDispute(uint256 auctionId, uint256 challengeIndex) internal {
        address accuser = challengeDisputeAccuser[auctionId][challengeIndex];
        BidChallenge memory challenge = auctionContract.getChallenge(auctionId, challengeIndex);
        address accused = challenge.challenger;

        uint256 accuserBond = challengeDisputeBond[auctionId][challengeIndex];
        uint256 accusedBond = auctionContract.getParticipationBond(auctionId, accused);

        if (challengeGuilty[auctionId][challengeIndex]) {
            // Challenger guilty: accuser gets their bond back, challenger's participation bond is slashed
            _safeTransfer(payable(accuser), accuserBond);
            auctionContract.updateParticipationBond(auctionId, accused, 0);

            emit DisputeResolved(auctionId, accuser, accuserBond + accusedBond);
        } else {
            // Challenger not guilty: challenger receives the accuser's bond
            _safeTransfer(payable(accused), accuserBond);
            emit DisputeResolved(auctionId, accused, accuserBond);
        }

        // Clean up state
        challengeDisputeAccuser[auctionId][challengeIndex] = address(0);
        challengeDisputeBond[auctionId][challengeIndex] = 0;
        emit DisputeResponded(auctionId, accused, challengeGuilty[auctionId][challengeIndex]);
    }

    // ==================== Helper Functions ====================
    
    /**
     * @dev Safe transfer function
     * @param to Recipient address
     * @param amount Transfer amount
     */
    function _safeTransfer(address payable to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    // ==================== Bond Refund ====================
    
    /**
     * @dev Participant claims their participation bond
     * @param auctionId Auction ID
     * @param caller Claimant address
     * @notice Can only be claimed after the dispute period ends
     */
    function claimParticipationBond(uint256 auctionId, address caller) external {
        bool settled = settlementContract.isAuctionSettled(auctionId);
        bool failed = settlementContract.isAuctionFailed(auctionId);
        require(settled || failed, "Auction not settled");

        uint256 settlementTime = settlementContract.getSettlementTimestamp(auctionId);
        require(block.timestamp > settlementTime + DISPUTE_PERIOD, "Dispute period not ended");

        uint256 amount = auctionContract.getParticipationBond(auctionId, caller);
        if (amount == 0) revert NotAuthorized();

        // Call the auction contract's refund function
        auctionContract.refundBond(auctionId, caller);

        emit BondRefunded(auctionId, caller, amount);
    }

    // ==================== View Functions ====================
    
    /**
     * @dev Gets seller dispute information
     * @param auctionId Auction ID
     * @return accuser Accuser address
     * @return startTime Accusation start time
     * @return bondAmount Bond amount
     * @return responded Whether responded
     * @return guilty Whether found guilty
     */
    function getSellerDisputeInfo(
        uint256 auctionId
    )
        external
        view
        returns (
            address accuser,
            uint256 startTime,
            uint256 bondAmount,
            bool responded,
            bool guilty
        )
    {
        return (
            sellerDisputeAccuser[auctionId],
            sellerDisputeStart[auctionId],
            sellerDisputeBond[auctionId],
            sellerDisputeResponded[auctionId],
            sellerGuilty[auctionId]
        );
    }

    // ==================== Security Fallback ====================
    
    /**
     * @dev Prevents fallback calls
     */
    fallback() external payable {
        revert FallbackNotAllowed();
    }

    /**
     * @dev Allows receiving ETH (for bonds)
     */
    receive() external payable {}
}