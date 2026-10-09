// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DecisionHub} from "../DecisionHub.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8, bytes32, bytes32);
    function prank(address sender) external;
    function deal(address who, uint256 amount) external;
    function warp(uint256 timestamp) external;
}

contract DecisionHubTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY = 0x1234;
    DecisionHub private hub;
    address private user;

    function setUp() public {
        hub = new DecisionHub(vm.addr(KEY));
        user = vm.addr(0x5678);
        vm.deal(user, 10 ether);
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
        hub.registerTemplate(keccak256("template-v1"), keccak256("jev-1.13.0"),
            kinds, sizes, minProb, minConf, review);
    }

    function _signature(bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _request() internal returns (uint256 id) {
        DecisionHub.Quote memory q = DecisionHub.Quote(user, user, address(this), 1,
            keccak256("proposal"), uint64(block.timestamp + 120), 1, 1 ether,
            uint64(block.timestamp + 30));
        bytes memory signature = _signature(hub.quoteDigest(q));
        vm.prank(user);
        id = hub.requestDecision{value: 1 ether}(q, signature);
    }

    function _answers(uint32 probability) internal pure returns (DecisionHub.Answer[] memory a) {
        a = new DecisionHub.Answer[](2);
        uint32[] memory distribution = new uint32[](4);
        distribution[0] = probability;
        distribution[1] = 1_000_000 - probability;
        a[0] = DecisionHub.Answer(1, 0, 0, 800_000, distribution);
        a[1] = DecisionHub.Answer(3, 0, 900_000, 0, new uint32[](0));
    }

    function testReadyConsumeOnceAndFee() public {
        uint256 id = _request();
        DecisionHub.Answer[] memory answers = _answers(950_000);
        bytes32 evidence = keccak256("evidence");
        bytes32 model = keccak256("jev-1.13.0");
        bytes memory signature = _signature(hub.resultDigest(id, keccak256(abi.encode(answers)), evidence, model, 1));
        hub.fulfill(id, answers, evidence, model, signature);
        DecisionHub.Request memory readyRequest = hub.getRequest(id);
        require(readyRequest.status == DecisionHub.Status.Ready, "not ready");
        bytes memory encoded = hub.consume(id);
        require(keccak256(encoded) == keccak256(abi.encode(answers)), "wrong answers");
        DecisionHub.Request memory consumedRequest = hub.getRequest(id);
        require(consumedRequest.status == DecisionHub.Status.Consumed, "not consumed");
        require(hub.serviceBalance() == 1 ether, "fee missing");
        (bool ok,) = address(hub).call(abi.encodeCall(hub.consume, (id)));
        require(!ok, "double consume");
    }

    function testExpirationRefundAndLateFulfill() public {
        uint256 id = _request();
        vm.warp(block.timestamp + 121);
        hub.expire(id);
        require(hub.refundCredits(user) == 1 ether, "refund missing");
        DecisionHub.Answer[] memory answers = _answers(950_000);
        (bool ok,) = address(hub).call(abi.encodeCall(hub.fulfill,
            (id, answers, keccak256("evidence"), keccak256("jev-1.13.0"), hex"")));
        require(!ok, "late fulfill accepted");
        vm.prank(user);
        hub.withdrawRefund();
        require(hub.refundCredits(user) == 0, "refund not cleared");
    }

    function testLowProbabilityGoesToReview() public {
        uint256 id = _request();
        DecisionHub.Answer[] memory answers = _answers(850_000);
        bytes32 evidence = keccak256("evidence");
        bytes32 model = keccak256("jev-1.13.0");
        bytes memory signature = _signature(hub.resultDigest(id, keccak256(abi.encode(answers)), evidence, model, 1));
        hub.fulfill(id, answers, evidence, model, signature);
        DecisionHub.Request memory request = hub.getRequest(id);
        require(request.status == DecisionHub.Status.Review, "not review");
        (bool ok,) = address(hub).call(abi.encodeCall(hub.consume, (id)));
        require(!ok, "review result consumed");
    }

    function testRevokedSignerAllowsImmediateRefund() public {
        uint256 id = _request();
        hub.revokeSigner(1);
        hub.expire(id);
        require(hub.refundCredits(user) == 1 ether, "revoked signer refund missing");
    }

    function testQuoteIsBoundToRefund() public {
        DecisionHub.Quote memory q = DecisionHub.Quote(user, user, address(this), 1,
            keccak256("proposal"), uint64(block.timestamp + 120), 1, 1 ether,
            uint64(block.timestamp + 30));
        bytes memory signature = _signature(hub.quoteDigest(q));
        q.refundTo = address(this);
        vm.prank(user);
        (bool ok,) = address(hub).call{value: 1 ether}(abi.encodeCall(hub.requestDecision, (q, signature)));
        require(!ok, "changed refund accepted");
    }

    function testPauseOnlyStopsNewRequests() public {
        uint256 existing = _request();
        hub.setRequestsPaused(true);
        DecisionHub.Quote memory q = DecisionHub.Quote(user, user, address(this), 1,
            keccak256("another"), uint64(block.timestamp + 120), 1, 1 ether,
            uint64(block.timestamp + 30));
        bytes memory signature = _signature(hub.quoteDigest(q));
        vm.prank(user);
        (bool ok,) = address(hub).call{value: 1 ether}(abi.encodeCall(hub.requestDecision, (q, signature)));
        require(!ok, "paused request accepted");
        DecisionHub.Request memory request = hub.getRequest(existing);
        require(request.status == DecisionHub.Status.Pending, "existing request changed");
        hub.setRequestsPaused(false);
    }
    function testWrongModelAndTamperedAnswersRejected() public {
        uint256 id = _request();
        DecisionHub.Answer[] memory answers = _answers(950_000);
        bytes32 evidence = keccak256("evidence");
        bytes32 model = keccak256("jev-1.13.0");
        bytes memory signature = _signature(hub.resultDigest(id, keccak256(abi.encode(answers)), evidence, model, 1));
        (bool ok,) = address(hub).call(abi.encodeCall(hub.fulfill,
            (id, answers, evidence, keccak256("other-model"), signature)));
        require(!ok, "wrong model accepted");
        answers[0].confidencePpm = 900_000;
        (ok,) = address(hub).call(abi.encodeCall(hub.fulfill, (id, answers, evidence, model, signature)));
        require(!ok, "tampered answers accepted");
        require(hub.getRequest(id).status == DecisionHub.Status.Pending, "failed fulfillment changed status");
    }

    function testDuplicateFulfillmentAndForeignConsumerRejected() public {
        uint256 id = _request();
        DecisionHub.Answer[] memory answers = _answers(950_000);
        bytes32 evidence = keccak256("evidence");
        bytes32 model = keccak256("jev-1.13.0");
        bytes memory signature = _signature(hub.resultDigest(id, keccak256(abi.encode(answers)), evidence, model, 1));
        hub.fulfill(id, answers, evidence, model, signature);
        (bool ok,) = address(hub).call(abi.encodeCall(hub.fulfill, (id, answers, evidence, model, signature)));
        require(!ok && hub.serviceBalance() == 1 ether, "duplicate charged twice");
        vm.prank(user);
        (ok,) = address(hub).call(abi.encodeCall(hub.consume, (id)));
        require(!ok, "foreign consumer accepted");
        require(hub.getRequest(id).status == DecisionHub.Status.Ready, "foreign consumer changed status");
    }

}
