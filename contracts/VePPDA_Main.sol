// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Import dependent contracts
import "./GlobalsStruct.sol";
import "./VePPDA_Auction.sol";
import "./VePPDA_Dispute.sol";
import "./VePPDA_Settlement.sol";

/**
 * @title VePPDA_Main
 * @dev Main contract: coordinates the core logic of the auction, settlement, and dispute modules
 * @notice Serves as the system entry point, manages bonds, verifies permissions, and routes function calls
 */
contract VePPDA_Main {
    // ==================== External Contract References ====================
    VePPDA_Auction public auctionContract;
    VePPDA_Dispute public disputeContract;
    VePPDA_Settlement public settlementContract;

    // ==================== Configuration Constants ====================
    /// @dev Participation bond amount
    uint256 public constant PARTICIPATION_BOND = 0.1 ether;

    /// @dev Dispute bond amount
    uint256 public constant DISPUTE_BOND = 0.1 ether;

    // ==================== Event Definitions ====================
    /// @notice Emitted when contracts are linked
    event ContractsLinked(
        address indexed auctionContract,
        address indexed disputeContract,
        address indexed settlementContract
    );

    /// @notice Emitted when an auction is created
    event AuctionCreated(
        uint256 indexed auctionId,
        address indexed seller,
        string info,
        uint256 startPrice,
        uint256 duration,
        uint256 length,
        bytes verifyParameters,
        bytes commitment
    );

    // ==================== Error Definitions ====================

    error InvalidContractAddress();
    error InvalidAuctionState();
    error OnlyWinnerCanChallengeReserve();
    error ReserveChallengeAlreadyExist();
    error Unauthorized();

    // ==================== Constructor ====================
    /**
     * @dev Initializes the contract by setting the addresses of the three core modules
     * @param _auctionContract Address of the auction contract
     * @param _disputeContract Address of the dispute contract
     * @param _settlementContract Address of the settlement contract
     */
    constructor(
        address _auctionContract,
        address _disputeContract,
        address _settlementContract
    ) {
        // Validate contract addresses
        if (
            _auctionContract == address(0) ||
            _disputeContract == address(0) ||
            _settlementContract == address(0)
        ) revert InvalidContractAddress();

        // Initialize contract references
        auctionContract = VePPDA_Auction(payable(_auctionContract));
        disputeContract = VePPDA_Dispute(payable(_disputeContract));
        settlementContract = VePPDA_Settlement(payable(_settlementContract));

        // Emit event
        emit ContractsLinked(
            _auctionContract,
            _disputeContract,
            _settlementContract
        );
    }

    // ==================== Auction Management Functions ====================

    /**
     * @dev Creates a new auction
     * @param params Auction parameters structure
     * @notice The caller must pay the participation bond
     */
    function createAuction(AuctionParams memory params) external payable {
        require(
            msg.value == PARTICIPATION_BOND,
            "Must send participation bond"
        );
        uint256 id = auctionContract.createAuction{value: msg.value}(
            params,
            msg.sender
        );

        emit AuctionCreated(
            id,
            msg.sender,
            params.info,
            params.startPrice,
            params.duration,
            params.length,
            params.verifyParameters,
            params.commitment
        );
    }

    /**
     * @dev Claims a bid
     * @param auctionId Auction ID
     * @param buyerPks Buyer's public key
     * @param verifyParameters Verification parameters
     * @param eps Encryption parameters
     * @param commitment Commitment data
     * @notice The caller must pay the participation bond
     */
    function claimBid(
        uint256 auctionId,
        PublicKeys calldata buyerPks,
        bytes calldata verifyParameters,
        EncryptParameters calldata eps,
        bytes calldata commitment
    ) external payable {
        require(
            msg.value == PARTICIPATION_BOND,
            "Must send participation bond"
        );
        auctionContract.claimBid{value: msg.value}(
            auctionId,
            buyerPks,
            verifyParameters,
            eps,
            commitment,
            msg.sender
        );
    }

    /**
     * @dev Challenges a bid claim
     * @param auctionId Auction ID
     * @param bidClaimIndex Index of the bid claim
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment data
     * @notice The caller must pay the participation bond
     */
    function challengeBid(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata challengeParameters,
        bytes calldata commitment
    ) external payable {
        require(
            msg.value == PARTICIPATION_BOND,
            "Must send participation bond"
        );
        auctionContract.challengeBid{value: msg.value}(
            auctionId,
            bidClaimIndex,
            challengeParameters,
            commitment,
            msg.sender
        );
    }

    /**
     * @dev Responds to a challenge
     * @param auctionId Auction ID
     * @param bidClaimIndex Index of the bid claim
     * @param m Decryption parameter
     * @param r Response value
     */
    function respondToChallenge(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata m,
        int256 r
    ) external {
        auctionContract.respondToChallenge(
            auctionId,
            bidClaimIndex,
            m,
            r,
            msg.sender
        );
    }

    /**
     * @dev Claims a bid after a successful challenge
     * @param auctionId Auction ID
     * @param challengedBidIndex Index of the challenged bid
     * @param buyerPks Buyer's public key
     * @param verifyParameters Verification parameters
     * @param eps Encryption parameters
     * @param commitment Commitment data
     * @notice The caller must pay the participation bond
     */
    function claimBidAfterSuccessfulChallenge(
        uint256 auctionId,
        uint256 challengedBidIndex,
        PublicKeys calldata buyerPks,
        bytes calldata verifyParameters,
        EncryptParameters calldata eps,
        bytes calldata commitment
    ) external payable {
        require(
            msg.value == PARTICIPATION_BOND,
            "Must send participation bond"
        );
        auctionContract.claimBidAfterSuccessfulChallenge{value: msg.value}(
            auctionId,
            challengedBidIndex,
            buyerPks,
            verifyParameters,
            eps,
            commitment,
            msg.sender
        );
    }

    // ==================== Settlement Management Functions ====================

    /**
     * @dev Settles an auction
     * @param auctionId Auction ID
     */
    function settleAuction(uint256 auctionId) external {
        settlementContract.settleAuction(auctionId);
    }

    /**
     * @dev Final stage bid challenge
     * @param auctionId Auction ID
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment data
     */
    function challengeBidFinal(
        uint256 auctionId,
        bytes calldata challengeParameters,
        bytes calldata commitment
    ) external {
        settlementContract.challengeBidFinal(
            auctionId,
            challengeParameters,
            commitment,
            msg.sender
        );
    }

    /**
     * @dev Responds to a final stage challenge
     * @param auctionId Auction ID
     * @param m Decryption parameter
     * @param r Response value
     */
    function respondToChallengeFinal(
        uint256 auctionId,
        bytes calldata m,
        int256 r
    ) external {
        settlementContract.respondToChallengeFinal(auctionId, m, r, msg.sender);
    }

    /**
     * @dev Finalizes a challenge by timeout
     * @param auctionId Auction ID
     */
    function finalizeChallengeByTimeout(uint256 auctionId) external {
        settlementContract.finalizeChallengeByTimeout(auctionId);
    }

    /**
     * @dev Challenges the reserve price (only callable by the winner)
     * @param auctionId Auction ID
     * @param challengeParameters Challenge parameters (encrypted value)
     * @param commitment Challenge commitment
     * @notice 1. Verifies auction state 2. Verifies caller identity 3. Checks for an existing active challenge
     */
    function challengeReserve(
        uint256 auctionId,
        bytes calldata challengeParameters,
        bytes calldata commitment
    ) external payable {
        // Validate auction state
        require(
            settlementContract.isAuctionSettled(auctionId),
            "Auction not settled"
        );
        require(
            !settlementContract.isAuctionFailed(auctionId),
            "Auction failed"
        );

        // Verify caller is the winner
        address winner = settlementContract.getAuctionWinner(auctionId);
        if (msg.sender != winner) revert OnlyWinnerCanChallengeReserve();

        // Check for existing active challenge
        if (settlementContract.isReserveChallengeActive(auctionId)) {
            revert ReserveChallengeAlreadyExist();
        }

        // Forward to settlement contract
        require(
            msg.value == PARTICIPATION_BOND,
            "Must send participation bond"
        );
        settlementContract.challengeReserve{value: msg.value}(
            auctionId,
            challengeParameters,
            commitment,
            msg.sender
        );
    }

    /**
     * @dev Responds to a reserve challenge (only callable by the seller)
     * @param auctionId Auction ID
     * @param m Decryption parameter
     * @param r Response value
     */
    function respondToChallengeReserve(
        uint256 auctionId,
        bytes calldata m,
        int256 r
    ) external {
        // Verify caller is the seller
        address seller = auctionContract.getAuctionSeller(auctionId);
        if (msg.sender != seller) revert Unauthorized();

        // Forward to settlement contract
        settlementContract.respondToChallengeReserve(
            auctionId,
            m,
            r,
            msg.sender
        );
    }

    // ==================== Dispute Handling Functions ====================

    /**
     * @dev Accuses the seller of malicious behavior
     * @param auctionId Auction ID
     * @notice The caller must pay the dispute bond
     */
    function accuseSellerMalicious(uint256 auctionId) external payable {
        require(msg.value == DISPUTE_BOND, "Must send dispute bond");
        disputeContract.accuseSellerMalicious{value: msg.value}(
            auctionId,
            msg.sender
        );
    }

    /**
     * @dev Seller responds to a dispute
     * @param auctionId Auction ID
     * @param revealedReservePrice Revealed reserve price
     * @param revealedRandomness Revealed randomness
     */
    function respondSellerDispute(
        uint256 auctionId,
        uint256 revealedReservePrice,
        bytes memory revealedRandomness
    ) external {
        disputeContract.respondSellerDispute(
            auctionId,
            revealedReservePrice,
            revealedRandomness,
            msg.sender
        );
    }

    /**
     * @dev Accuses a bidder of malicious behavior
     * @param auctionId Auction ID
     * @param bidClaimIndex Index of the bid claim
     * @notice The caller must pay the dispute bond
     */
    function accuseBidderMalicious(
        uint256 auctionId,
        uint256 bidClaimIndex
    ) external payable {
        require(msg.value == DISPUTE_BOND, "Must send dispute bond");
        disputeContract.accuseBidderMalicious{value: msg.value}(
            auctionId,
            bidClaimIndex,
            msg.sender
        );
    }

    /**
     * @dev Bidder responds to a dispute
     * @param auctionId Auction ID
     * @param bidClaimIndex Index of the bid claim
     * @param revealedBidPrice Revealed bid price
     * @param revealedRandomness Revealed randomness
     */
    function respondBidderDispute(
        uint256 auctionId,
        uint256 bidClaimIndex,
        uint256 revealedBidPrice,
        bytes memory revealedRandomness
    ) external {
        disputeContract.respondBidderDispute(
            auctionId,
            bidClaimIndex,
            revealedBidPrice,
            revealedRandomness,
            msg.sender
        );
    }

    /**
     * @dev Accuses a challenger of malicious behavior
     * @param auctionId Auction ID
     * @param challengeIndex Index of the challenge
     * @notice The caller must pay the dispute bond
     */
    function accuseChallengerMalicious(
        uint256 auctionId,
        uint256 challengeIndex
    ) external payable {
        require(msg.value == DISPUTE_BOND, "Must send dispute bond");
        disputeContract.accuseChallengerMalicious{value: msg.value}(
            auctionId,
            challengeIndex,
            msg.sender
        );
    }

    /**
     * @dev Challenger responds to a dispute
     * @param auctionId Auction ID
     * @param challengeIndex Index of the challenge
     * @param revealedChallengerBid Revealed challenger's bid
     * @param revealedChallengeValue Revealed challenge value
     * @param revealedChallengeRandomness Revealed challenge randomness
     */
    function respondChallengerDispute(
        uint256 auctionId,
        uint256 challengeIndex,
        uint256 revealedChallengerBid,
        bytes memory revealedChallengeValue,
        bytes memory revealedChallengeRandomness
    ) external {
        disputeContract.respondChallengerDispute(
            auctionId,
            challengeIndex,
            revealedChallengerBid,
            revealedChallengeValue,
            revealedChallengeRandomness,
            msg.sender
        );
    }

    /**
     * @dev Finalizes a challenger dispute (automatic processing on timeout)
     * @param auctionId Auction ID
     * @param challengeIndex Index of the challenge
     */
    function finalizeChallengerDispute(uint256 auctionId, uint256 challengeIndex) external {
       disputeContract.finalizeChallengerDispute(auctionId, challengeIndex);
    }

    // ==================== Bond Management Functions ====================

    /**
     * @dev Claims the participation bond
     * @param auctionId Auction ID
     */
    function claimParticipationBond(uint256 auctionId) external payable {
        auctionContract.refundBond(auctionId, msg.sender);
    }

    // ==================== View Query Functions ====================

    /**
     * @dev Gets auction details
     * @param _auctionId Auction ID
     * @return Auction structure
     */
    function getAuction(
        uint256 _auctionId
    ) external view returns (Auction memory) {
        return auctionContract.getAuction(_auctionId);
    }

    /**
     * @dev Gets the list of valid bids
     * @param auctionId Auction ID
     * @return Array of BidClaim
     */
    function getValidAuctionBids(
        uint256 auctionId
    ) external view returns (BidClaim[] memory) {
        return auctionContract.getValidAuctionBids(auctionId);
    }

    /**
     * @notice Gets the challenge details for a specific bid
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @return Challenge structure
     */
    function getChallengeForBidClaim(
        uint256 auctionId,
        uint256 bidClaimIndex
    ) external view returns (BidChallenge memory) {
        return
            auctionContract.getChallengeForBidClaim(auctionId, bidClaimIndex);
    }

    /**
     * @dev Gets the settlement stage information
     * @param auctionId Auction ID
     * @return SettlementStage structure
     */
    function getSettlementStage(
        uint256 auctionId
    ) external view returns (SettlementStage memory) {
        return settlementContract.getSettlementStage(auctionId);
    }

    /**
     * @dev Gets the auction winner address
     * @param auctionId Auction ID
     * @return Winner address
     */
    function getAuctionWinner(
        uint256 auctionId
    ) external view returns (address) {
        return settlementContract.getAuctionWinner(auctionId);
    }

    /**
     * @dev Gets reserve challenge information
     * @param auctionId Auction ID
     * @return Reserve challenge structure
     */
    function getReserveChallenge(
        uint256 auctionId
    ) external view returns (ReserveChallenge memory) {
        // Destructure to get each field from the mapping return
        (
            address challenger,
            bytes memory challengeParameters,
            bytes memory commitment,
            uint256 timestamp,
            bool isResolved,
            bool isSuccessful
        ) = settlementContract.reserveChallenges(auctionId);

        // Manually assemble and return the structure
        return
            ReserveChallenge(
                challenger,
                challengeParameters,
                commitment,
                timestamp,
                isResolved,
                isSuccessful
            );
    }

    /**
     * @dev Checks if an auction is settled
     * @param auctionId Auction ID
     * @return bool Whether settled
     */
    function isAuctionSettled(uint256 auctionId) external view returns (bool) {
        return settlementContract.isAuctionSettled(auctionId);
    }

    /**
     * @dev Checks if an auction failed
     * @param auctionId Auction ID
     * @return bool Whether failed
     */
    function isAuctionFailed(uint256 auctionId) external view returns (bool) {
        return settlementContract.isAuctionFailed(auctionId);
    }

    /**
     * @dev Checks if there is an active reserve challenge
     * @param auctionId Auction ID
     * @return bool Whether active
     */
    function isReserveChallengeActive(
        uint256 auctionId
    ) external view returns (bool) {
        return settlementContract.isReserveChallengeActive(auctionId);
    }

    /**
     * @notice Gets the participation bond amount for a participant
     * @param auctionId Auction ID
     * @param participant Participant address
     * @return Bond amount
     */
    function getParticipationBond(
        uint256 auctionId,
        address participant
    ) external view returns (uint256) {
        return auctionContract.participationBonds(auctionId, participant);
    }

    /**
     * @notice Gets the number of challenges for an auction
     * @param auctionId Auction ID
     * @return Length of challenges array
     */
    function auctionChallengesLength(
        uint256 auctionId
    ) external view returns (uint256) {
        return auctionContract.auctionChallengesLength(auctionId);
    }

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
        return disputeContract.getSellerDisputeInfo(auctionId);
    }

    /**
     * @dev Gets the settlement timestamp
     * @param auctionId Auction ID
     * @return Settlement timestamp
     */
    function getSettlementTimestamp(
        uint256 auctionId
    ) external view returns (uint256) {
        return settlementContract.getSettlementTimestamp(auctionId);
    }

    // ==================== Security Fallback Functions ====================

    /// @dev Rejects all undefined function calls
    fallback() external payable {
        revert("Fallback not allowed");
    }

    /// @dev Allows receiving Ether
    receive() external payable {}
}