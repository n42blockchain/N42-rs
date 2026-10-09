// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DecisionHub} from "../DecisionHub.sol";

/// @notice Public proposal example. AI classification routes review only;
/// funding decisions remain with the application's ordinary governance.
contract ProposalRouter {
    struct Proposal {
        address author;
        bytes32 inputHash;
        uint256 requestId;
        uint8 category;
        bool routed;
        bool humanResolution;
    }

    DecisionHub public immutable hub;
    uint64 public immutable templateId;
    address public immutable reviewer;
    mapping(bytes32 => Proposal) public proposals;

    event ProposalSubmitted(bytes32 indexed proposalKey, uint256 indexed requestId, bytes state);
    event ProposalRouted(bytes32 indexed proposalKey, uint8 category, bool byHuman);

    constructor(DecisionHub _hub, uint64 _templateId, address _reviewer) {
        require(address(_hub) != address(0) && _reviewer != address(0), "bad setup");
        hub = _hub;
        templateId = _templateId;
        reviewer = _reviewer;
    }

    function submit(bytes32 proposalKey, bytes calldata state, DecisionHub.Quote calldata quote,
        bytes calldata quoteSignature) external payable returns (uint256 requestId) {
        require(proposalKey != bytes32(0) && proposals[proposalKey].requestId == 0, "duplicate proposal");
        require(state.length > 0 && state.length <= 4096, "state size");
        require(quote.requester == address(this) && quote.consumer == address(this)
            && quote.refundTo == msg.sender && quote.templateId == templateId
            && quote.inputHash == keccak256(state), "quote does not bind proposal");
        requestId = hub.requestDecision{value: msg.value}(quote, quoteSignature);
        proposals[proposalKey] = Proposal(msg.sender, quote.inputHash, requestId, 0, false, false);
        emit ProposalSubmitted(proposalKey, requestId, state);
    }

    function route(bytes32 proposalKey) external {
        Proposal storage proposal = proposals[proposalKey];
        require(proposal.requestId != 0 && !proposal.routed, "not routable");
        bytes memory data = hub.consume(proposal.requestId);
        DecisionHub.Answer[] memory answers = abi.decode(data, (DecisionHub.Answer[]));
        require(answers.length == 2 && answers[0].kind == 1 && answers[1].kind == 3, "wrong template");
        require(answers[0].selected < 3, "requires review");
        proposal.category = answers[0].selected;
        proposal.routed = true;
        emit ProposalRouted(proposalKey, proposal.category, false);
    }

    function resolveReview(bytes32 proposalKey, uint8 category) external {
        require(msg.sender == reviewer && category < 3, "reviewer or category");
        Proposal storage proposal = proposals[proposalKey];
        require(proposal.requestId != 0 && !proposal.routed, "not reviewable");
        DecisionHub.Request memory r = hub.getRequest(proposal.requestId);
        require(r.status == DecisionHub.Status.Review, "AI did not request review");
        proposal.category = category;
        proposal.routed = true;
        proposal.humanResolution = true;
        emit ProposalRouted(proposalKey, category, true);
    }
}
