// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Asynchronous, operator-attested Jev decisions. The operator attests
/// to a response; this contract cannot prove the response came from Jev.
contract DecisionHub {
    uint32 public constant PPM = 1_000_000;
    uint8 public constant MAX_QUESTIONS = 8;
    uint8 public constant MAX_OPTIONS = 16;
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant QUOTE_TYPEHASH = keccak256(
        "Quote(address requester,address refundTo,address consumer,uint64 templateId,bytes32 inputHash,uint64 deadline,uint64 signerVersion,uint256 fee,uint64 quoteExpiry)"
    );
    bytes32 private constant RESULT_TYPEHASH = keccak256(
        "ResultAttestation(uint256 requestId,bytes32 answerHash,bytes32 evidenceHash,bytes32 modelHash,uint64 signerVersion)"
    );
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    enum Status { Pending, Ready, Review, Consumed, Expired }

    struct Template {
        bytes32 documentHash;
        bytes32 modelHash;
        bool active;
        uint8[] kinds; // 1 Choice, 2 Score, 3 Noul
        uint8[] sizes; // Choice options or Score levels; 0 for Noul
        uint32[] minProbabilityPpm;
        uint32[] minConfidencePpm;
        uint8[] reviewOption; // Choice index; 255 disables
    }

    struct Quote {
        address requester;
        address refundTo;
        address consumer;
        uint64 templateId;
        bytes32 inputHash;
        uint64 deadline;
        uint64 signerVersion;
        uint256 fee;
        uint64 quoteExpiry;
    }

    struct Answer {
        uint8 kind;
        uint8 selected;
        uint32 valuePpm;
        uint32 confidencePpm;
        uint32[] probabilitiesPpm;
    }

    struct Request {
        address requester;
        address refundTo;
        address consumer;
        uint64 templateId;
        uint64 deadline;
        uint64 signerVersion;
        bytes32 inputHash;
        bytes32 answerHash;
        bytes32 evidenceHash;
        uint256 fee;
        Status status;
        bytes answers;
    }

    address public immutable owner;
    bool public requestsPaused;
    uint64 public templateCount;
    uint64 public activeSignerVersion;
    uint256 public nextRequestId = 1;
    uint256 public serviceBalance;
    mapping(uint64 => Template) private templates;
    mapping(uint64 => address) public signerAt;
    mapping(uint64 => bool) public signerRevoked;
    mapping(uint256 => Request) private requests;
    mapping(address => uint256) public refundCredits;

    event TemplateRegistered(uint64 indexed id, bytes32 indexed documentHash, bytes32 modelHash);
    event DecisionRequested(uint256 indexed requestId, uint64 indexed templateId, bytes32 indexed inputHash, address requester, address consumer);
    event DecisionFulfilled(uint256 indexed requestId, Status status, bytes32 answerHash, bytes32 evidenceHash);
    event DecisionConsumed(uint256 indexed requestId, address indexed consumer);
    event DecisionExpired(uint256 indexed requestId, address indexed refundTo, uint256 amount);
    event SignerAdded(uint64 indexed version, address signer);
    event SignerRevoked(uint64 indexed version);
    event RequestsPaused(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner only");
        _;
    }

    constructor(address initialSigner) {
        require(initialSigner != address(0), "zero signer");
        owner = msg.sender;
        activeSignerVersion = 1;
        signerAt[1] = initialSigner;
        emit SignerAdded(1, initialSigner);
    }

    function addSigner(address signer) external onlyOwner {
        require(signer != address(0), "zero signer");
        uint64 version = activeSignerVersion + 1;
        activeSignerVersion = version;
        signerAt[version] = signer;
        emit SignerAdded(version, signer);
    }

    function revokeSigner(uint64 version) external onlyOwner {
        require(signerAt[version] != address(0), "unknown signer");
        signerRevoked[version] = true;
        emit SignerRevoked(version);
    }

    function setRequestsPaused(bool paused) external onlyOwner {
        requestsPaused = paused;
        emit RequestsPaused(paused);
    }

    function registerTemplate(
        bytes32 documentHash,
        bytes32 modelHash,
        uint8[] calldata kinds,
        uint8[] calldata sizes,
        uint32[] calldata minProbabilityPpm,
        uint32[] calldata minConfidencePpm,
        uint8[] calldata reviewOption
    ) external onlyOwner returns (uint64 id) {
        uint256 n = kinds.length;
        require(documentHash != bytes32(0) && modelHash != bytes32(0), "missing hash");
        require(n > 0 && n <= MAX_QUESTIONS, "question count");
        require(n == sizes.length && n == minProbabilityPpm.length && n == minConfidencePpm.length && n == reviewOption.length, "schema lengths");
        for (uint256 i; i < n; ++i) {
            require(minProbabilityPpm[i] <= PPM && minConfidencePpm[i] <= PPM, "threshold range");
            if (kinds[i] == 1) {
                require(sizes[i] >= 2 && sizes[i] <= MAX_OPTIONS, "choice size");
                require(reviewOption[i] == 255 || reviewOption[i] < sizes[i], "review index");
            } else if (kinds[i] == 2) {
                require(sizes[i] >= 2 && sizes[i] <= 10 && reviewOption[i] == 255, "score size");
            } else {
                require(kinds[i] == 3 && sizes[i] == 0 && reviewOption[i] == 255, "noul schema");
            }
        }
        id = ++templateCount;
        Template storage t = templates[id];
        t.documentHash = documentHash;
        t.modelHash = modelHash;
        t.active = true;
        t.kinds = kinds;
        t.sizes = sizes;
        t.minProbabilityPpm = minProbabilityPpm;
        t.minConfidencePpm = minConfidencePpm;
        t.reviewOption = reviewOption;
        emit TemplateRegistered(id, documentHash, modelHash);
    }

    function disableTemplate(uint64 id) external onlyOwner {
        require(templates[id].active, "inactive template");
        templates[id].active = false;
    }

    function getTemplate(uint64 id) external view returns (Template memory) {
        return templates[id];
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("N42Decision"), keccak256("1"), block.chainid, address(this)));
    }

    function quoteDigest(Quote calldata q) public view returns (bytes32) {
        bytes32 hash = keccak256(abi.encode(QUOTE_TYPEHASH, q.requester, q.refundTo, q.consumer,
            q.templateId, q.inputHash, q.deadline, q.signerVersion, q.fee, q.quoteExpiry));
        return _typedDigest(hash);
    }

    function resultDigest(uint256 requestId, bytes32 answerHash, bytes32 evidenceHash,
        bytes32 modelHash, uint64 signerVersion) public view returns (bytes32) {
        return _typedDigest(keccak256(abi.encode(RESULT_TYPEHASH, requestId, answerHash,
            evidenceHash, modelHash, signerVersion)));
    }

    function _typedDigest(bytes32 messageHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), messageHash));
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        require(uint256(s) <= SECP256K1_HALF_N && uint256(s) != 0, "signature s");
        require(v == 27 || v == 28, "signature v");
        return ecrecover(digest, v, r, s);
    }

    function _authenticated(uint64 version, bytes32 digest, bytes calldata signature) internal view {
        address signer = signerAt[version];
        require(signer != address(0) && !signerRevoked[version], "signer unavailable");
        require(_recover(digest, signature) == signer, "bad signer");
    }

    function requestDecision(Quote calldata q, bytes calldata signature) external payable returns (uint256 requestId) {
        require(!requestsPaused, "requests paused");
        require(q.requester == msg.sender && q.refundTo != address(0), "quote parties");
        require(q.inputHash != bytes32(0) && templates[q.templateId].active, "input or template");
        require(q.signerVersion == activeSignerVersion, "stale signer");
        require(q.deadline > block.timestamp && q.deadline <= block.timestamp + 1 days, "deadline");
        require(q.quoteExpiry >= block.timestamp && q.quoteExpiry <= q.deadline, "quote expired");
        require(msg.value == q.fee, "fee mismatch");
        _authenticated(q.signerVersion, quoteDigest(q), signature);
        requestId = nextRequestId++;
        Request storage r = requests[requestId];
        r.requester = q.requester;
        r.refundTo = q.refundTo;
        r.consumer = q.consumer;
        r.templateId = q.templateId;
        r.deadline = q.deadline;
        r.signerVersion = q.signerVersion;
        r.inputHash = q.inputHash;
        r.fee = q.fee;
        emit DecisionRequested(requestId, q.templateId, q.inputHash, q.requester, q.consumer);
    }

    function fulfill(uint256 requestId, Answer[] calldata answers, bytes32 evidenceHash,
        bytes32 modelHash, bytes calldata signature) external {
        Request storage r = requests[requestId];
        require(r.requester != address(0) && r.status == Status.Pending, "not pending");
        require(block.timestamp < r.deadline, "deadline reached");
        require(evidenceHash != bytes32(0), "missing evidence");
        Template storage t = templates[r.templateId];
        require(modelHash == t.modelHash, "model mismatch");
        bytes32 answerHash = keccak256(abi.encode(answers));
        _authenticated(r.signerVersion, resultDigest(requestId, answerHash, evidenceHash,
            modelHash, r.signerVersion), signature);
        bool review = _validateAnswers(t, answers);
        r.status = review ? Status.Review : Status.Ready;
        r.answerHash = answerHash;
        r.evidenceHash = evidenceHash;
        r.answers = abi.encode(answers);
        serviceBalance += r.fee;
        emit DecisionFulfilled(requestId, r.status, answerHash, evidenceHash);
    }

    function _validateAnswers(Template storage t, Answer[] calldata answers) internal view returns (bool review) {
        require(answers.length == t.kinds.length, "answer count");
        for (uint256 i; i < answers.length; ++i) {
            Answer calldata a = answers[i];
            uint8 size = t.sizes[i];
            require(a.kind == t.kinds[i], "answer type");
            require(a.valuePpm <= uint32(size > 0 ? uint256(size - 1) * PPM : PPM), "value range");
            require(a.confidencePpm <= PPM, "confidence range");
            if (a.kind == 3) {
                require(size == 0 && a.selected == 0 && a.confidencePpm == 0
                    && a.probabilitiesPpm.length == 0, "noul shape");
                if (a.valuePpm < t.minProbabilityPpm[i]) review = true;
                continue;
            }
            require(a.probabilitiesPpm.length == size && a.selected < size, "distribution shape");
            uint256 sum;
            uint32 maxProbability;
            for (uint256 j; j < size; ++j) {
                uint32 p = a.probabilitiesPpm[j];
                require(p <= PPM, "probability range");
                sum += p;
                if (p > maxProbability) maxProbability = p;
            }
            require(sum <= PPM && sum + size >= PPM, "distribution sum");
            if (a.kind == 1) {
                require(a.valuePpm == 0 && a.probabilitiesPpm[a.selected] == maxProbability, "choice mismatch");
                if (maxProbability < t.minProbabilityPpm[i] || a.confidencePpm < t.minConfidencePpm[i]
                    || a.selected == t.reviewOption[i]) review = true;
            } else {
                require(a.selected == 0, "score shape");
                if (a.confidencePpm < t.minConfidencePpm[i]) review = true;
            }
        }
    }

    function getRequest(uint256 requestId) external view returns (Request memory) {
        require(requests[requestId].requester != address(0), "unknown request");
        return requests[requestId];
    }

    function consume(uint256 requestId) external returns (bytes memory answers) {
        Request storage r = requests[requestId];
        require(r.consumer == msg.sender && r.consumer != address(0), "wrong consumer");
        require(r.status == Status.Ready, "not ready");
        r.status = Status.Consumed;
        emit DecisionConsumed(requestId, msg.sender);
        return r.answers;
    }

    function expire(uint256 requestId) external {
        Request storage r = requests[requestId];
        require(r.requester != address(0) && r.status == Status.Pending, "not pending");
        require(block.timestamp >= r.deadline || signerRevoked[r.signerVersion], "not expired");
        r.status = Status.Expired;
        refundCredits[r.refundTo] += r.fee;
        emit DecisionExpired(requestId, r.refundTo, r.fee);
    }

    function withdrawRefund() external {
        uint256 amount = refundCredits[msg.sender];
        require(amount > 0, "no refund");
        refundCredits[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "refund failed");
    }

    function withdrawServiceFees(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0) && amount <= serviceBalance, "fee withdrawal");
        serviceBalance -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "fee transfer failed");
    }
}
