// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {DecisionHub} from "../DecisionHub.sol";
import {ProposalRouter} from "../examples/ProposalRouter.sol";
import {Vm} from "./DecisionHub.t.sol";

contract ProposalRouterTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY = 0x1234;
    DecisionHub private hub;
    ProposalRouter private router;
    bytes32 private constant PROPOSAL = keccak256("public-proposal");

    function setUp() public {
        hub = new DecisionHub(vm.addr(KEY));
        uint8[] memory kinds = new uint8[](2);
        kinds[0] = 1; kinds[1] = 3;
        uint8[] memory sizes = new uint8[](2);
        sizes[0] = 4;
        uint32[] memory minProb = new uint32[](2);
        minProb[0] = 900_000; minProb[1] = 800_000;
        uint32[] memory minConf = new uint32[](2);
        minConf[0] = 700_000;
        uint8[] memory review = new uint8[](2);
        review[0] = 3; review[1] = 255;
        hub.registerTemplate(keccak256("template-v1"), keccak256("jev-1.13.0"), kinds, sizes, minProb, minConf, review);
        router = new ProposalRouter(hub, 1, address(this));
        vm.deal(address(this), 10 ether);
    }

    function sign(bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function submitAndFulfill(uint32 probability) private returns (uint256 id) {
        bytes memory state = bytes("public input");
        DecisionHub.Quote memory q = DecisionHub.Quote(address(router), address(this), address(router), 1,
            keccak256(state), uint64(block.timestamp + 120), 1, 1 ether, uint64(block.timestamp + 30));
        bytes memory signature = sign(hub.quoteDigest(q));
        id = router.submit{value: 1 ether}(PROPOSAL, state, q, signature);
        (bool ok,) = address(router).call{value: 1 ether}(abi.encodeCall(router.submit, (PROPOSAL, state, q, signature)));
        require(!ok, "duplicate proposal accepted");
        DecisionHub.Answer[] memory answers = new DecisionHub.Answer[](2);
        uint32[] memory probabilities = new uint32[](4);
        probabilities[0] = probability; probabilities[1] = 1_000_000 - probability;
        answers[0] = DecisionHub.Answer(1, 0, 0, 800_000, probabilities);
        answers[1] = DecisionHub.Answer(3, 0, 900_000, 0, new uint32[](0));
        bytes32 evidence = keccak256("evidence");
        bytes32 model = keccak256("jev-1.13.0");
        hub.fulfill(id, answers, evidence, model,
            sign(hub.resultDigest(id, keccak256(abi.encode(answers)), evidence, model, 1)));
    }

    function testReadyRoutesPermissionlesslyOnce() public {
        uint256 id = submitAndFulfill(950_000);
        vm.prank(address(0x999));
        router.route(PROPOSAL);
        require(hub.getRequest(id).status == DecisionHub.Status.Consumed, "not consumed");
        (,,,, bool routed, bool human) = router.proposals(PROPOSAL);
        require(routed && !human, "routing flags");
        (bool ok,) = address(router).call(abi.encodeCall(router.route, (PROPOSAL)));
        require(!ok, "double route");
    }

    function testReviewRequiresReviewerAndCannotAutoRoute() public {
        uint256 id = submitAndFulfill(850_000);
        (bool ok,) = address(router).call(abi.encodeCall(router.route, (PROPOSAL)));
        require(!ok && hub.getRequest(id).status == DecisionHub.Status.Review, "review auto-routed");
        vm.prank(address(0x999));
        (ok,) = address(router).call(abi.encodeCall(router.resolveReview, (PROPOSAL, 1)));
        require(!ok, "foreign reviewer accepted");
        (ok,) = address(router).call(abi.encodeCall(router.resolveReview, (PROPOSAL, 3)));
        require(!ok, "review category accepted");
        router.resolveReview(PROPOSAL, 1);
        (,,, uint8 category, bool routed, bool human) = router.proposals(PROPOSAL);
        require(category == 1 && routed && human, "review flags");
        (ok,) = address(router).call(abi.encodeCall(router.resolveReview, (PROPOSAL, 2)));
        require(!ok, "double review");
    }
}
