import { ethers, network, config } from "hardhat";
import { Transaction } from "ethereumjs-tx";

async function checkIfContractExists() { // Get the provider from the Hardhat Runtime Environment
  const address =
  "0x00000961Ef480Eb55e80D19ad83579A64c007002";
  const provider = ethers.provider;

  // Use the getCode method to check for bytecode at the address
  const bytecode = await provider.getCode(address);

  // Check if the returned bytecode is anything other than '0x'
  if (bytecode === '0x') {
    console.log(`No contract found at address: ${address}`);
    return false;
  } else {
    console.log(`Contract found at address: ${address}`);
    return true;
  }
}



export async function deployExit() {
  const transactionData = {
    type: '0x0',
    nonce: '0x0',
    to: undefined,
    gasPrice: '0xe8d4a51000',
    gasLimit: '0x3d090',
    value: '0x0',
    data: '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f556101f880602d5f395ff33373fffffffffffffffffffffffffffffffffffffffe1460cb5760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff146101f457600182026001905f5b5f82111560685781019083028483029004916001019190604d565b909390049250505036603814608857366101f457346101f4575f5260205ff35b34106101f457600154600101600155600354806003026004013381556001015f35815560010160203590553360601b5f5260385f601437604c5fa0600101600355005b6003546002548082038060101160df575060105b5f5b8181146101835782810160030260040181604c02815460601b8152601401816001015481526020019060020154807fffffffffffffffffffffffffffffffff00000000000000000000000000000000168252906010019060401c908160381c81600701538160301c81600601538160281c81600501538160201c81600401538160181c81600301538160101c81600201538160081c81600101535360010160e1565b910180921461019557906002556101a0565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff14156101cd57505f5b6001546002828201116101e25750505f6101e8565b01600290035b5f555f600155604c025ff35b5f5ffd',
    v: '0x1b',
    r: '0x539',
    s: '0x5feeb084551e4e03a3581e269bc2ea2f8d0008',
};

  const exitDeploySenderAddress = "0x8646861A7cF453dDD086874d622b0696dE5b9674";
  const amountToSendWei: bigint = ethers.parseEther("1.0");
  const provider = ethers.getDefaultProvider((network.config as any).url);
  const balance = await provider.getBalance(exitDeploySenderAddress);
  console.log("balance", balance)
  // Get the signer (the account that will send the ETH).
  // In Hardhat, `ethers.getSigners()` gets the accounts configured in your
  // network.
  // The first signer (index 0) will be the one associated with the
  // PRIVATE_KEY in your .env.
  const [sender] = await ethers.getSigners();

  console.log(`Sender account: ${sender.address}`);
  const senderBalance = await ethers.provider.getBalance(sender.address);
  console.log(`Sender balance before: ${ethers.formatEther(senderBalance)} ETH`);
  try {
    // --- Perform the transfer ---
    // A simple transaction object to send native ETH.
    const transaction = {
      to: exitDeploySenderAddress,
      value: amountToSendWei,
    };

    console.log("Sending transaction...");
    let txResponse = await sender.sendTransaction(transaction);
    console.log(`Transaction hash: ${txResponse.hash}`);

    // Wait for the transaction to be mined and get the receipt.
    console.log("Waiting for transaction to be confirmed...");
    let txReceipt = await txResponse.wait();
    if (txReceipt && txReceipt.status === 1) { // status 1 means success
      console.log(`Transaction confirmed in block: ${txReceipt.blockNumber}`);
      console.log(`Gas used: ${txReceipt.gasUsed.toString()}`);
    }

    const currentNonce = await provider.getTransactionCount(exitDeploySenderAddress);
    console.log(`exitDeploySenderAddress ${exitDeploySenderAddress} current nonce: ${currentNonce}`);

    const txNonce = parseInt(transactionData.nonce, 16);
    if (txNonce !== currentNonce) {
        console.warn(`⚠️ Warning: Provided transaction nonce (${txNonce}) does not match sender's current nonce (${currentNonce}).`);
        console.warn("This might cause the transaction to fail or be considered invalid. Please ensure the transaction's nonce is correct.");
    }
    const tx = new Transaction(transactionData);

    const serializedTx = tx.serialize().toString('hex');
    const rawTransactionHex = '0x' + serializedTx;
    txResponse = await provider.broadcastTransaction(rawTransactionHex);

    txReceipt = await txResponse.wait();

    if (txReceipt && txReceipt.status === 1) { // status 1 means success, 0 means reverted
      console.log(`\n🎉 Transaction successfully confirmed in block ${txReceipt.blockNumber}!`);
    }
  } catch (error: any) {
    console.log(error);
  }
}

export default async function globalSetup() {
  let contractInstalled = await checkIfContractExists();
  if (contractInstalled) {
    console.log(`check contract ok`);
    return;
  }
  // Get the ContractFactory for DepositContract
  const DepositContractFactory = await ethers.getContractFactory("DepositContract");

  // Deploy the contract with an initial greeting
  const myContract = await DepositContractFactory.deploy();

  // Wait for the deployment to be mined
  await myContract.waitForDeployment();

  // Log the deployed address
  console.log(`DepositContract deployed to: ${myContract.target}`);

  await deployExit();
}
