// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import "@eigenlayer/contracts/permissions/Pausable.sol";
import "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {RegistryCoordinator} from "@eigenlayer-middleware/src/RegistryCoordinator.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "@eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {OperatorStateRetriever} from "@eigenlayer-middleware/src/OperatorStateRetriever.sol";
import "@eigenlayer-middleware/src/libraries/BN254.sol";
import "./IIncredibleSquaringTaskManager.sol";

contract IncredibleSquaringTaskManager is
    Initializable,
    OwnableUpgradeable,
    Pausable,
    BLSSignatureChecker,
    OperatorStateRetriever,
    IIncredibleSquaringTaskManager
{
    using BN254 for BN254.G1Point;

    /* CONSTANT */
    uint32 public immutable TASK_RESPONSE_WINDOW_BLOCK;
    uint32 public constant TASK_CHALLENGE_WINDOW_BLOCK = 100;
    uint256 internal constant _THRESHOLD_DENOMINATOR = 100;

    /* STORAGE */
    uint32 public latestTaskNum;
    mapping(uint32 => bytes32) public allTaskHashes;
    mapping(uint32 => bytes32) public allTaskResponses;
    mapping(uint32 => bool) public taskSuccesfullyChallenged;
    // mapping(address => bool) public generator;
    mapping(address => uint32) public generator; // stacker add with stack amount
    address public aggregator;
    

    // New job mappings
    uint32 public latestJobId;
    struct Job {
        uint32 jobId;
        string jobType;
        address jobContractadd;
        string jobDescription;
        string status;
        bytes quorumNumbers;
        uint32 quorumThresholdPercentage;
        uint32 timeframe;
        string gitlink;
    }
    mapping(uint32 => Job) public jobs;

    /* MODIFIERS */
    modifier onlyAggregator() {
        require(msg.sender.address == aggregator[], "Aggregator must be the caller");
        _;
    }

    modifier onlyTaskGenerator() {
        // stack ammound must be greater tjan 32 ETH.
        require( generator[msg.sender] >= 32, "Task generator must be the caller"); 
        _;
    }

    constructor(
        IRegistryCoordinator _registryCoordinator,
        uint32 _taskResponseWindowBlock
    ) BLSSignatureChecker(_registryCoordinator) {
        TASK_RESPONSE_WINDOW_BLOCK = _taskResponseWindowBlock;
    }

    function initialize(
        IPauserRegistry _pauserRegistry,
        address initialOwner,
        address _aggregator,
        address _generator,
        uint32 stackamount
    ) public initializer {
        _initializePauser(_pauserRegistry, UNPAUSE_ALL);
        _transferOwnership(initialOwner);
        aggregator = _aggregator;
        // generator = _generator;
        generator[_generator]=stackamount;
    }

    /* EVENTS */
    event JobCreated(uint32 indexed jobId, string jobType, string jobDescription, address jobContractadd, string gitlink);
    event JobDeleted(uint32 indexed jobId);
    event TaskEvent(uint32 indexed jobId, string jobType, string jobDescription, string status, address jobContractadd, string gitlink);
    event JobStatusUpdated(uint32 indexed jobId, string status);
    event JobAssigned(uint32 indexed jobId, string jobType, address operator);

    /* FUNCTIONS */
    function createJob(
        string calldata jobType,
        string calldata jobDescription,
        address jobContractadd,
        string gitlink,
        string calldata status,
        bytes calldata quorumNumbers,
        uint32 quorumThresholdPercentage,
        uint32 timeframe
    ) external onlyTaskGenerator {
        latestJobId++;
        Job memory newJob = Job({
            jobId: latestJobId,
            jobType: jobType,
            gitlink: gitlink,
            jobContractadd: jobContractadd,
            jobDescription: jobDescription,
            status: status,
            quorumNumbers: quorumNumbers,
            quorumThresholdPercentage: quorumThresholdPercentage,
            timeframe: timeframe
        });
        jobs[latestJobId] = newJob;
        emit JobCreated(latestJobId, jobType, jobDescription, jobContractadd, gitlink);
    }

    function deleteJob(uint32 jobId) external onlyTaskGenerator {
        require(jobs[jobId].jobId != 0, "Job does not exist");
        delete jobs[jobId];
        emit JobDeleted(jobId);
    }

    function emitTaskEvent(uint32 jobId, string calldata status,address jobContractadd,string gitlink) external onlyTaskGenerator {
        Job storage job = jobs[jobId];
        require(job.jobId != 0, "Job does not exist");
        emit TaskEvent(jobId, job.jobType, job.jobDescription, status, jobContractadd, gitlink);
    }

    function updateJobStatus(uint32 jobId, string calldata status) external onlyTaskGenerator {
        Job storage job = jobs[jobId];
        require(job.jobId != 0, "Job does not exist");
        job.status = status;
        emit JobStatusUpdated(jobId, status);
    }

    function assignJob(uint32 jobId, address operator) external onlyTaskGenerator {
        Job storage job = jobs[jobId];
        require(job.jobId != 0, "Job does not exist");
        emit JobAssigned(jobId, job.jobType, operator);
    }

    function createNewTask(
        uint256 numberToBeSquared,
        uint32 quorumThresholdPercentage,
        address jobContractadd,
        string gitlink,
        bytes calldata quorumNumbers
    ) external onlyTaskGenerator {
        Task memory newTask;
        newTask.numberToBeSquared = numberToBeSquared;
        newTask.taskCreatedBlock = uint32(block.number);
        newTask.quorumThresholdPercentage = quorumThresholdPercentage;
        newTask.jobContractadd = jobContractadd;
        newTask.gitlink = gitlink;
        newTask.quorumNumbers = quorumNumbers;

        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        latestTaskNum = latestTaskNum + 1;
    }

    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external onlyAggregator {
        uint32 taskCreatedBlock = task.taskCreatedBlock;
        bytes calldata quorumNumbers = task.quorumNumbers;
        uint32 quorumThresholdPercentage = task.quorumThresholdPercentage;

        require(
            keccak256(abi.encode(task)) ==
                allTaskHashes[taskResponse.referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(
            allTaskResponses[taskResponse.referenceTaskIndex] == bytes32(0),
            "Aggregator has already responded to the task"
        );
        require(
            uint32(block.number) <=
                taskCreatedBlock + TASK_RESPONSE_WINDOW_BLOCK,
            "Aggregator has responded to the task too late"
        );

        bytes32 message = keccak256(abi.encode(taskResponse));

        (
            QuorumStakeTotals memory quorumStakeTotals,
            bytes32 hashOfNonSigners
        ) = checkSignatures(
                message,
                quorumNumbers,
                taskCreatedBlock,
                nonSignerStakesAndSignature
            );

        for (uint i = 0; i < quorumNumbers.length; i++) {
            require(
                quorumStakeTotals.signedStakeForQuorum[i] *
                    _THRESHOLD_DENOMINATOR >=
                    quorumStakeTotals.totalStakeForQuorum[i] *
                        uint8(quorumThresholdPercentage),
                "Signatories do not own at least threshold percentage of a quorum"
            );
        }

        TaskResponseMetadata memory taskResponseMetadata = TaskResponseMetadata(
            uint32(block.number),
            hashOfNonSigners
        );
        allTaskResponses[taskResponse.referenceTaskIndex] = keccak256(
            abi.encode(taskResponse, taskResponseMetadata)
        );

        emit TaskResponded(taskResponse, taskResponseMetadata);
    }

    function taskNumber() external view returns (uint32) {
        return latestTaskNum;
    }

    function raiseAndResolveChallenge(
        Task calldata task,
        TaskResponse calldata taskResponse,
        TaskResponseMetadata calldata taskResponseMetadata,
        BN254.G1Point[] memory pubkeysOfNonSigningOperators
    ) external {
        uint32 referenceTaskIndex = taskResponse.referenceTaskIndex;
        uint256 numberToBeSquared = task.numberToBeSquared;
        require(
            allTaskResponses[referenceTaskIndex] != bytes32(0),
            "Task hasn't been responded to yet"
        );
        require(
            allTaskResponses[referenceTaskIndex] ==
                keccak256(abi.encode(taskResponse, taskResponseMetadata)),
            "Task response does not match the one recorded in the contract"
        );
        require(
            taskSuccesfullyChallenged[referenceTaskIndex] == false,
            "The response to this task has already been challenged successfully."
        );

        require(
            uint32(block.number) <=
                taskResponseMetadata.taskResponsedBlock +
                    TASK_CHALLENGE_WINDOW_BLOCK,
            "The challenge period for this task has already expired."
        );

        uint256 actualSquaredOutput = numberToBeSquared * numberToBeSquared;
        bool isResponseCorrect = (actualSquaredOutput ==
            taskResponse.numberSquared);

        if (isResponseCorrect == true) {
            emit TaskChallengedUnsuccessfully(referenceTaskIndex, msg.sender);
            return;
        }

        bytes32[] memory hashesOfPubkeysOfNonSigningOperators = new bytes32[](
            pubkeysOfNonSigningOperators.length
        );
        for (uint i = 0; i < pubkeysOfNonSigningOperators.length; i++) {
            hashesOfPubkeysOfNonSigningOperators[
                i
            ] = pubkeysOfNonSigningOperators[i].hashG1Point();
        }

        bytes32 signatoryRecordHash = keccak256(
            abi.encodePacked(
                task.taskCreatedBlock,
                hashesOfPubkeysOfNonSigningOperators
            )
        );
    }
}
    