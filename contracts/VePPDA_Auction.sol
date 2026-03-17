// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./GlobalsStruct.sol";

/**
 * @title VePPDA_Auction
 * @notice Privacy-preserving auction contract based on Paillier homomorphic encryption, supporting anonymous bidding and challenge mechanisms,
 *         allowing users to bid anonymously and ensuring bid validity through a verification system.
 */
contract VePPDA_Auction {

    // ==================== State Variables ====================
    
    /// @notice Mapping from auction ID to auction details
    mapping(uint256 => Auction) public auctions;
    
    /// @notice Auction counter, used to generate unique auction IDs
    uint256 public auctionCounter;

    /// @notice Mapping from auction ID to bid claims
    mapping(uint256 => BidClaim[]) public auctionBids;
    
    /// @notice Index of the latest bid by a bidder in a specific auction
    mapping(uint256 => mapping(address => uint256)) public bidderLatestBidIndex;

    /// @notice Mapping from auction ID to bid challenges
    mapping(uint256 => BidChallenge[]) public auctionChallenges;
    
    /// @notice Marks whether a specific bid has been challenged
    mapping(uint256 => mapping(uint256 => bool)) public isBidClaimChallenged;
    
    /// @notice Mapping from bid claim index to challenge index
    mapping(uint256 => mapping(uint256 => uint256)) public bidClaimToChallengeIndex;

    /// @notice Mapping from auction ID to challenge responses
    mapping(uint256 => ChallengeResponse[]) public auctionChallengeResponses;
    
    /// @notice Marks whether a challenge has been responded to
    mapping(uint256 => mapping(uint256 => bool)) public isChallengeResponseSubmitted;

    /// @notice Mapping of successful challenger addresses (auction ID => bid index => successful challenger address)
    mapping(uint256 => mapping(uint256 => address)) public challengeSuccessor;

    /// @notice Mapping of participation bonds (auction ID => participant address => bond amount)
    mapping(uint256 => mapping(address => uint256)) public participationBonds;

    // ==================== Configuration Constants ====================
    
    /// @notice Challenge response time window (1 minute)
    uint256 public constant CHALLENGE_RESPONSE_TIME = 1 minutes;
    
    /// @notice Maximum bid cache size
    uint256 public constant MAX_BID_CACHE_SIZE = 2;
    
    /// @notice Participation bond amount (0.1 ETH)
    uint256 public constant PARTICIPATION_BOND = 0.1 ether;

    // ==================== Error Definitions ====================
    
    // Auction related errors
    error InvalidAuctionID();
    error AuctionNotActive();
    error AuctionAlreadyEnded();
    
    // Parameter validation errors
    error InvalidStartPrice();
    error InvalidDuration();
    error InvalidLength();
    error BidCacheFull();
    error InvalidParameters();
    
    // Challenge related errors
    error CannotChallengeOwnBid();
    error SellerCannotChallenge();
    error BidAlreadyChallenged();
    error BidNotFound();
    error OnlyChallengedBidderCanRespond();
    error ChallengeNotActive();
    error ChallengeAlreadyResponded();
    error ChallengeTimeout();
    error InvalidChallengeResponse();
    
    // Permission related errors
    error OnlySellerCanCloseAuction();
    error Unauthorized();
    
    // Bond related errors
    error IncorrectBondAmount();
    error FallbackNotAllowed();
    error BondTransferFailed();

    // ==================== Event Definitions ====================
    

    /// @notice Event emitted when a bid is claimed
    event BidClaimed(
        uint256 indexed auctionId,
        address indexed bidder,
        bytes verifyParameters,
        bytes commitment,
        uint256 timestamp
    );

    /// @notice Event emitted when a bid is challenged
    event BidChallenged(
        uint256 indexed auctionId,
        uint256 indexed bidClaimIndex,
        address indexed challenger,
        bytes challengeParameters,
        bytes commitment,
        uint256 timestamp
    );

    /// @notice Event emitted when a challenge is responded to
    event ChallengeResponded(
        uint256 indexed auctionId,
        uint256 indexed bidClaimIndex,
        address indexed responder,
        int256 r,
        uint256 timestamp
    );

    /// @notice Event emitted when a challenge result is determined
    event ChallengeResult(
        uint256 indexed auctionId,
        uint256 indexed bidClaimIndex,
        bool isSuccessful,
        address indexed challenger,
        address newBidder
    );

    /// @notice Event emitted when a bid is invalidated
    event BidInvalidated(
        uint256 indexed auctionId,
        uint256 indexed bidClaimIndex,
        address indexed bidder,
        string reason
    );

    /// @notice Event emitted when a bond is deposited
    event BondDeposited(
        uint256 indexed auctionId,
        address indexed participant,
        uint256 amount
    );

    // ==================== Modifiers ====================
    
    /**
     * @notice Validates the auction ID
     * @param auctionId The auction ID to validate
     */
    modifier onlyValidAuction(uint256 auctionId) {
        if (auctionId == 0 || auctionId > auctionCounter)
            revert InvalidAuctionID();
        _;
    }

    // ==================== Core Functions ====================

    /**
     * @notice Creates a new auction
     * @dev Requires payment of a participation bond. Returns the newly created auction ID upon success.
     * @param params Auction parameters structure
     * @param caller Caller address
     * @return The newly created auction ID
     */
    function createAuction(
        AuctionParams memory params,
        address caller
    ) external payable returns (uint256) {
        // Validate bond amount
        if (msg.value != PARTICIPATION_BOND)
            revert IncorrectBondAmount();

        // Parameter validation
        if (params.startPrice == 0) revert InvalidStartPrice();
        if (params.duration == 0) revert InvalidDuration();
        if (params.length == 0 || params.length > MAX_BID_CACHE_SIZE)
            revert InvalidLength();

        // Generate auction ID
        uint256 id = ++auctionCounter;

        // Create auction record
        auctions[id] = Auction({
            seller: caller,
            info: params.info,
            startPrice: params.startPrice,
            duration: params.duration,
            length: params.length,
            pks: params.pks,
            verifyParameters: params.verifyParameters,
            eps: params.eps,
            commitment: params.commitment,
            startTime: block.timestamp,
            isActive: true
        });

        // Record seller's bond
        participationBonds[id][caller] = msg.value;
        // Emit event
        emit BondDeposited(id, caller, msg.value);

        return id;
    }

    /**
     * @notice Claims a bid
     * @dev Requires payment of a participation bond. Submits a bid claim within the auction active period.
     * @param auctionId Auction ID
     * @param buyerPks Buyer's public key
     * @param verifyParameters Verification parameters
     * @param eps Encryption parameters
     * @param commitment Commitment value
     * @param caller Caller address
     */
    function claimBid(
        uint256 auctionId,
        PublicKeys calldata buyerPks,
        bytes calldata verifyParameters,
        EncryptParameters calldata eps,
        bytes calldata commitment,
        address caller
    ) external payable onlyValidAuction(auctionId) {
        // Validate bond amount
        if (msg.value != PARTICIPATION_BOND)
            revert IncorrectBondAmount();

        Auction storage auction = auctions[auctionId];

        // Auction state validation
        if (!auction.isActive) revert AuctionNotActive();
        if (block.timestamp >= auction.startTime + auction.duration)
            revert AuctionAlreadyEnded();

        // Parameter validation
        if (verifyParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        BidClaim[] storage bids = auctionBids[auctionId];
        
        // Check if bid cache is full
        if (bids.length >= auction.length) revert BidCacheFull();

        // Add new bid claim
        uint256 bidIndex = bids.length;
        bids.push(
            BidClaim({
                bidder: caller,
                buyerPks: buyerPks,
                verifyParameters: verifyParameters,
                eps: eps,
                commitment: commitment,
                timestamp: block.timestamp,
                isValid: true
            })
        );

        // Update index and bond record
        bidderLatestBidIndex[auctionId][caller] = bidIndex;
        participationBonds[auctionId][caller] = msg.value;

        // Emit events
        emit BidClaimed(
            auctionId,
            caller,
            verifyParameters,
            commitment,
            block.timestamp
        );

        emit BondDeposited(auctionId, caller, msg.value);
    }

    /**
     * @notice Challenges a bid claim
     * @dev Challenger must pay a participation bond. Seller cannot challenge their own auction.
     * @param auctionId Auction ID
     * @param bidClaimIndex Index of the challenged bid
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment value
     * @param caller Challenger address
     */
    function challengeBid(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata challengeParameters,
        bytes calldata commitment,
        address caller
    ) external payable onlyValidAuction(auctionId) {
        // Validate bond amount
        if (msg.value != PARTICIPATION_BOND)
            revert IncorrectBondAmount();

        Auction storage auction = auctions[auctionId];

        // Auction state validation
        if (!auction.isActive) revert AuctionNotActive();
        if (block.timestamp >= auction.startTime + auction.duration)
            revert AuctionAlreadyEnded();
        
        // Permission validation: seller cannot challenge
        if (caller == auction.seller) revert SellerCannotChallenge();

        BidClaim[] storage bids = auctionBids[auctionId];
        
        // Bid validation
        if (bidClaimIndex >= bids.length) revert BidNotFound();
        if (!bids[bidClaimIndex].isValid) revert BidNotFound();
        if (bids[bidClaimIndex].bidder == caller)
            revert CannotChallengeOwnBid();
        if (isBidClaimChallenged[auctionId][bidClaimIndex])
            revert BidAlreadyChallenged();
        
        // Parameter validation
        if (challengeParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        // Create challenge record
        uint256 challengeIndex = auctionChallenges[auctionId].length;
        auctionChallenges[auctionId].push(
            BidChallenge({
                challenger: caller,
                bidClaimIndex: bidClaimIndex,
                challengeParameters: challengeParameters,
                commitment: commitment,
                timestamp: block.timestamp,
                isResolved: false,
                isSuccessful: false
            })
        );

        // Update state mappings
        isBidClaimChallenged[auctionId][bidClaimIndex] = true;
        bidClaimToChallengeIndex[auctionId][bidClaimIndex] = challengeIndex;
        participationBonds[auctionId][caller] = msg.value;

        // Emit events
        emit BidChallenged(
            auctionId,
            bidClaimIndex,
            caller,
            challengeParameters,
            commitment,
            block.timestamp
        );

        emit BondDeposited(auctionId, caller, msg.value);
    }

    /**
     * @notice Responds to a challenge
     * @dev The challenged bidder or the challenger after timeout can respond to the challenge.
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param m Response message
     * @param r Response result (1 indicates success)
     * @param caller Responder address
     */
    function respondToChallenge(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata m,
        int256 r,
        address caller
    ) external onlyValidAuction(auctionId) {
        Auction storage auction = auctions[auctionId];
        
        // Auction state validation
        if (
            !auction.isActive ||
            block.timestamp >= auction.startTime + auction.duration
        ) revert AuctionAlreadyEnded();

        // Bid validation
        if (bidClaimIndex >= auctionBids[auctionId].length)
            revert BidNotFound();
        if (!isBidClaimChallenged[auctionId][bidClaimIndex])
            revert ChallengeNotActive();

        uint256 challengeIndex = bidClaimToChallengeIndex[auctionId][
            bidClaimIndex
        ];

        // Check if already responded
        if (isChallengeResponseSubmitted[auctionId][challengeIndex])
            revert ChallengeAlreadyResponded();

        BidChallenge storage challenge = auctionChallenges[auctionId][
            challengeIndex
        ];
        BidClaim storage challengedBid = auctionBids[auctionId][bidClaimIndex];

        // Check if timeout
        bool isTimedOut = block.timestamp >
            challenge.timestamp + CHALLENGE_RESPONSE_TIME;

        bool isChallengeSuccessful;

        // Handle response based on timeout
        if (!isTimedOut) {
            // Not timed out: only challenged bidder can respond
            if (caller != challengedBid.bidder)
                revert OnlyChallengedBidderCanRespond();
            if (m.length == 0) revert InvalidParameters();
            isChallengeSuccessful = (r == 1);
        } else {
            // Timed out: challenge automatically succeeds
            isChallengeSuccessful = false;
        }

        // Record challenge response
        auctionChallengeResponses[auctionId].push(
            ChallengeResponse({
                bidClaimIndex: bidClaimIndex,
                challengeIndex: challengeIndex,
                m: m,
                r: r,
                responder: caller,
                timestamp: block.timestamp,
                isValid: true
            })
        );

        isChallengeResponseSubmitted[auctionId][challengeIndex] = true;

        // Update challenge state
        _updateChallengeState(
            auctionId,
            bidClaimIndex,
            challengeIndex,
            isChallengeSuccessful
        );

        // Emit event
        emit ChallengeResponded(
            auctionId,
            bidClaimIndex,
            caller,
            r,
            block.timestamp
        );
    }

    /**
     * @notice Updates challenge state (internal function)
     * @dev Processes challenge results and updates relevant state.
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param challengeIndex Challenge index
     * @param isChallengeSuccessful Whether the challenge was successful
     */
    function _updateChallengeState(
        uint256 auctionId,
        uint256 bidClaimIndex,
        uint256 challengeIndex,
        bool isChallengeSuccessful
    ) internal {
        BidChallenge storage challenge = auctionChallenges[auctionId][
            challengeIndex
        ];
        challenge.isResolved = true;
        challenge.isSuccessful = isChallengeSuccessful;

        if (isChallengeSuccessful) {
            // Challenge successful: bid remains valid, clear challenge flag
            isBidClaimChallenged[auctionId][bidClaimIndex] = false;
        } else {
            // Challenge failed: bid invalidated, challenger becomes new bidder
            auctionBids[auctionId][bidClaimIndex].isValid = false;
            isBidClaimChallenged[auctionId][bidClaimIndex] = false;

            challengeSuccessor[auctionId][bidClaimIndex] = challenge.challenger;

            emit BidInvalidated(
                auctionId,
                bidClaimIndex,
                auctionBids[auctionId][bidClaimIndex].bidder,
                "Challenge successful"
            );
        }

        // Emit challenge result event
        emit ChallengeResult(
            auctionId,
            bidClaimIndex,
            isChallengeSuccessful,
            challenge.challenger,
            isChallengeSuccessful ? address(0) : challenge.challenger
        );
    }

    /**
     * @notice Claims a bid after a successful challenge
     * @dev The successful challenger can replace the invalid bid.
     * @param auctionId Auction ID
     * @param challengedBidIndex Index of the challenged bid
     * @param buyerPks Buyer's public key
     * @param verifyParameters Verification parameters
     * @param eps Encryption parameters
     * @param commitment Commitment value (must match the challenge commitment)
     * @param caller Caller address
     */
    function claimBidAfterSuccessfulChallenge(
        uint256 auctionId,
        uint256 challengedBidIndex,
        PublicKeys calldata buyerPks,
        bytes calldata verifyParameters,
        EncryptParameters calldata eps,
        bytes calldata commitment,
        address caller
    ) external payable onlyValidAuction(auctionId) {
        // Validate bond amount
        if (msg.value != PARTICIPATION_BOND)
            revert IncorrectBondAmount();

        Auction storage auction = auctions[auctionId];

        // Auction state validation
        require(auction.isActive, "Auction not active");
        require(
            block.timestamp < auction.startTime + auction.duration,
            "Auction already ended"
        );

        BidClaim storage bid = auctionBids[auctionId][challengedBidIndex];
        
        // Bid state validation
        require(!bid.isValid, "Bid is still valid");

        // Permission validation: only successful challenger can replace
        require(
            challengeSuccessor[auctionId][challengedBidIndex] == caller,
            "Unauthorized"
        );

        // Parameter validation
        if (verifyParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        // Verify commitment matches the challenge commitment
        uint256 challengeIndex = bidClaimToChallengeIndex[auctionId][
            challengedBidIndex
        ];
        require(
            challengeIndex < auctionChallenges[auctionId].length,
            "Challenge not found"
        );

        require(
            keccak256(commitment) ==
                keccak256(
                    auctionChallenges[auctionId][challengeIndex].commitment
                ),
            "Commitment must match challenge commitment"
        );

        // Update bid information
        bid.bidder = caller;
        bid.buyerPks = buyerPks;
        bid.verifyParameters = verifyParameters;
        bid.eps = eps;
        bid.commitment = commitment;
        bid.timestamp = block.timestamp;
        bid.isValid = true;

        // Update index and bond record
        bidderLatestBidIndex[auctionId][caller] = challengedBidIndex;
        participationBonds[auctionId][caller] = msg.value;

        // Emit events
        emit BidClaimed(
            auctionId,
            caller,
            verifyParameters,
            commitment,
            block.timestamp
        );

        emit BondDeposited(auctionId, caller, msg.value);
    }

    /**
     * @notice Final stage challenge for a bid
     * @dev Final challenge phase after auction ends, no bond required.
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param challengeParameters Challenge parameters
     * @param commitment Commitment value
     * @param caller Challenger address
     */
    function challengeBidFinal(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata challengeParameters,
        bytes calldata commitment,
        address caller
    ) external onlyValidAuction(auctionId) {
        Auction storage auction = auctions[auctionId];

        // Auction state validation
        if (!auction.isActive) revert AuctionNotActive();

        // Permission validation: seller cannot challenge
        if (caller == auction.seller) revert SellerCannotChallenge();

        BidClaim[] storage bids = auctionBids[auctionId];
        
        // Bid validation
        if (bidClaimIndex >= bids.length) revert BidNotFound();
        if (!bids[bidClaimIndex].isValid) revert BidNotFound();
        if (bids[bidClaimIndex].bidder == caller)
            revert CannotChallengeOwnBid();
        if (isBidClaimChallenged[auctionId][bidClaimIndex])
            revert BidAlreadyChallenged();
        
        // Parameter validation
        if (challengeParameters.length == 0 || commitment.length == 0)
            revert InvalidParameters();

        // Create challenge record
        uint256 challengeIndex = auctionChallenges[auctionId].length;
        auctionChallenges[auctionId].push(
            BidChallenge({
                challenger: caller,
                bidClaimIndex: bidClaimIndex,
                challengeParameters: challengeParameters,
                commitment: commitment,
                timestamp: block.timestamp,
                isResolved: false,
                isSuccessful: false
            })
        );

        // Update state mappings
        isBidClaimChallenged[auctionId][bidClaimIndex] = true;
        bidClaimToChallengeIndex[auctionId][bidClaimIndex] = challengeIndex;

        // Emit event
        emit BidChallenged(
            auctionId,
            bidClaimIndex,
            caller,
            challengeParameters,
            commitment,
            block.timestamp
        );
    }

    /**
     * @notice Responds to a final stage challenge
     * @dev Handles responses for the final challenge phase.
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @param m Response message
     * @param r Response result
     * @param caller Responder address
     */
    function respondToChallengeFinal(
        uint256 auctionId,
        uint256 bidClaimIndex,
        bytes calldata m,
        int256 r,
        address caller
    ) external onlyValidAuction(auctionId) {
        // Bid validation
        if (bidClaimIndex >= auctionBids[auctionId].length)
            revert BidNotFound();
        if (!isBidClaimChallenged[auctionId][bidClaimIndex])
            revert ChallengeNotActive();

        uint256 challengeIndex = bidClaimToChallengeIndex[auctionId][
            bidClaimIndex
        ];

        // Check if already responded
        if (isChallengeResponseSubmitted[auctionId][challengeIndex])
            revert ChallengeAlreadyResponded();

        BidChallenge storage challenge = auctionChallenges[auctionId][
            challengeIndex
        ];
        BidClaim storage challengedBid = auctionBids[auctionId][bidClaimIndex];

        // Check if timeout
        bool isTimedOut = block.timestamp >
            challenge.timestamp + CHALLENGE_RESPONSE_TIME;

        bool isChallengeSuccessful;

        // Handle response based on timeout
        if (!isTimedOut) {
            // Not timed out: only challenged bidder can respond
            if (caller != challengedBid.bidder)
                revert OnlyChallengedBidderCanRespond();
            if (m.length == 0) revert InvalidParameters();
            isChallengeSuccessful = (r == 1);
        } else {
            // Timed out: only challenger can respond
            if (caller != challenge.challenger) revert ChallengeTimeout();
            isChallengeSuccessful = false;
        }

        // Record challenge response
        auctionChallengeResponses[auctionId].push(
            ChallengeResponse({
                bidClaimIndex: bidClaimIndex,
                challengeIndex: challengeIndex,
                m: m,
                r: r,
                responder: caller,
                timestamp: block.timestamp,
                isValid: true
            })
        );

        isChallengeResponseSubmitted[auctionId][challengeIndex] = true;

        // Update challenge state
        _updateChallengeState(
            auctionId,
            bidClaimIndex,
            challengeIndex,
            isChallengeSuccessful
        );

        // Emit event
        emit ChallengeResponded(
            auctionId,
            bidClaimIndex,
            caller,
            r,
            block.timestamp
        );
    }

    // ==================== View Functions ====================

    /**
     * @notice Gets auction details
     * @param _auctionId Auction ID
     * @return Auction structure
     */
    function getAuction(
        uint256 _auctionId
    ) external view returns (Auction memory) {
        if (_auctionId == 0 || _auctionId > auctionCounter)
            revert InvalidAuctionID();
        return auctions[_auctionId];
    }

    /**
     * @notice Gets the list of valid bids
     * @dev Returns only bids that are valid and not challenged.
     * @param auctionId Auction ID
     * @return Array of valid bid claims
     */
    function getValidAuctionBids(
        uint256 auctionId
    ) public view returns (BidClaim[] memory) {
        if (auctionId == 0 || auctionId > auctionCounter)
            revert InvalidAuctionID();

        BidClaim[] storage allBids = auctionBids[auctionId];
        uint256 validCount = 0;

        // Count valid bids
        for (uint256 i = 0; i < allBids.length; i++) {
            if (allBids[i].isValid && !isBidClaimChallenged[auctionId][i]) {
                validCount++;
            }
        }

        // Create and populate result array
        BidClaim[] memory validBids = new BidClaim[](validCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < allBids.length; i++) {
            if (allBids[i].isValid && !isBidClaimChallenged[auctionId][i]) {
                validBids[idx++] = allBids[i];
            }
        }

        return validBids;
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
        return participationBonds[auctionId][participant];
    }

    /**
     * @notice Gets the total number of auctions
     * @return Auction counter value
     */
    function getAuctionCount() external view returns (uint256) {
        return auctionCounter;
    }

    /**
     * @notice Checks if an auction is active
     * @param _auctionId Auction ID
     * @return Whether the auction is active (true/false)
     */
    function isAuctionActive(uint256 _auctionId) external view returns (bool) {
        if (_auctionId == 0 || _auctionId > auctionCounter)
            revert InvalidAuctionID();
        Auction storage auction = auctions[_auctionId];
        return
            auction.isActive &&
            (block.timestamp < auction.startTime + auction.duration);
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
        if (
            auctionId == 0 ||
            auctionId > auctionCounter ||
            bidClaimIndex >= auctionBids[auctionId].length ||
            !isBidClaimChallenged[auctionId][bidClaimIndex]
        ) {
            revert InvalidParameters();
        }
        uint256 challengeIndex = bidClaimToChallengeIndex[auctionId][
            bidClaimIndex
        ];
        return auctionChallenges[auctionId][challengeIndex];
    }

    /**
     * @notice Gets the auction seller address
     * @param auctionId Auction ID
     * @return Seller address
     */
    function getAuctionSeller(
        uint256 auctionId
    ) external view returns (address) {
        return auctions[auctionId].seller;
    }

    /**
     * @notice Checks if a bid is challenged (for settlement contract use)
     * @param auctionId Auction ID
     * @param bidClaimIndex Bid index
     * @return Whether the bid is challenged
     */
    function getisBidClaimChallenged(
        uint256 auctionId,
        uint256 bidClaimIndex
    ) external view returns (bool) {
        return isBidClaimChallenged[auctionId][bidClaimIndex];
    }

    /**
     * @notice Gets the result of a challenge
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     * @return isSuccessful Whether the challenge was successful
     */
    function getChallengeResult(
        uint256 auctionId,
        uint256 challengeIndex
    ) external view returns (bool isSuccessful) {
        if (challengeIndex >= auctionChallenges[auctionId].length) {
            revert("Invalid challenge index");
        }

        BidChallenge storage challenge = auctionChallenges[auctionId][
            challengeIndex
        ];
        return challenge.isSuccessful;
    }

    /**
     * @notice Gets the number of challenges for an auction
     * @param auctionId Auction ID
     * @return Length of challenges array
     */
    function auctionChallengesLength(
        uint256 auctionId
    ) external view returns (uint256) {
        return auctionChallenges[auctionId].length;
    }

    /**
     * @notice Gets the bid index associated with a challenge
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     * @return Bid index
     */
    function getChallengeBidIndex(
        uint256 auctionId,
        uint256 challengeIndex
    ) external view returns (uint256) {
        require(
            challengeIndex < auctionChallenges[auctionId].length,
            "Invalid challenge index"
        );
        return auctionChallenges[auctionId][challengeIndex].bidClaimIndex;
    }

    /**
     * @notice Gets challenge details
     * @param auctionId Auction ID
     * @param challengeIndex Challenge index
     * @return Challenge structure
     */
    function getChallenge(
        uint256 auctionId,
        uint256 challengeIndex
    ) external view returns (BidChallenge memory) {
        require(
            challengeIndex < auctionChallenges[auctionId].length,
            "Invalid challenge index"
        );
        return auctionChallenges[auctionId][challengeIndex];
    }

    // ==================== Bond Management Functions ====================

    /**
     * @notice Updates the participation bond amount for a participant
     * @dev Can be called by external contracts to adjust bonds.
     * @param auctionId Auction ID
     * @param participant Participant address
     * @param newAmount New bond amount
     */
    function updateParticipationBond(
        uint256 auctionId,
        address participant,
        uint256 newAmount
    ) external {
        participationBonds[auctionId][participant] = newAmount;
    }

    /**
     * @notice Transfers a bond between participants
     * @param auctionId Auction ID
     * @param from Sender address
     * @param to Recipient address
     * @param amount Transfer amount
     */
    function transferBond(
        uint256 auctionId,
        address from,
        address to,
        uint256 amount
    ) external {
        require(
            participationBonds[auctionId][from] >= amount,
            "Insufficient bond"
        );
        participationBonds[auctionId][from] -= amount;
        participationBonds[auctionId][to] += amount;
    }

    /**
     * @notice Refunds a bond to a participant
     * @dev Sends the bond back to the participant and zeroes their bond record.
     * @param auctionId Auction ID
     * @param participant Participant address
     */
    function refundBond(
        uint256 auctionId,
        address participant
    ) external {
        uint256 amount = participationBonds[auctionId][participant];
        participationBonds[auctionId][participant] = 0;

        (bool success, ) = payable(participant).call{value: amount}("");
        if (!success) revert BondTransferFailed();
    }

    // ==================== Security Fallback ====================

    /**
     * @notice Prevents accidental calls to the fallback function
     */
    fallback() external payable {
        revert FallbackNotAllowed();
    }

    /**
     * @notice Allows receiving Ether
     */
    receive() external payable {}
}