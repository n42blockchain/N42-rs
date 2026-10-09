export {keccak256} from './keccak.mjs';
import {keccak256} from './keccak.mjs';

export const quoteComponents = [
  {name:'requester',type:'address'}, {name:'refundTo',type:'address'},
  {name:'consumer',type:'address'}, {name:'templateId',type:'uint64'},
  {name:'inputHash',type:'bytes32'}, {name:'deadline',type:'uint64'},
  {name:'signerVersion',type:'uint64'}, {name:'fee',type:'uint256'},
  {name:'quoteExpiry',type:'uint64'}
];
export const hubAbi = [
  {type:'function',name:'requestDecision',stateMutability:'payable',inputs:[{name:'q',type:'tuple',components:quoteComponents},{name:'signature',type:'bytes'}],outputs:[{name:'requestId',type:'uint256'}]},
  {type:'function',name:'getRequest',stateMutability:'view',inputs:[{name:'requestId',type:'uint256'}],outputs:[{name:'request',type:'tuple',components:[
    {name:'requester',type:'address'},{name:'refundTo',type:'address'},{name:'consumer',type:'address'},
    {name:'templateId',type:'uint64'},{name:'deadline',type:'uint64'},{name:'signerVersion',type:'uint64'},
    {name:'inputHash',type:'bytes32'},{name:'answerHash',type:'bytes32'},{name:'evidenceHash',type:'bytes32'},
    {name:'fee',type:'uint256'},{name:'status',type:'uint8'},{name:'answers',type:'bytes'}]}]},
  {type:'function',name:'expire',stateMutability:'nonpayable',inputs:[{name:'requestId',type:'uint256'}],outputs:[]},
  {type:'function',name:'withdrawRefund',stateMutability:'nonpayable',inputs:[],outputs:[]}
];
export const routerAbi = [
  {type:'event',name:'ProposalSubmitted',inputs:[{name:'proposalKey',type:'bytes32',indexed:true},{name:'requestId',type:'uint256',indexed:true},{name:'state',type:'bytes',indexed:false}]},
  {type:'function',name:'submit',stateMutability:'payable',inputs:[{name:'proposalKey',type:'bytes32'},
    {name:'state',type:'bytes'},{name:'quote',type:'tuple',components:quoteComponents},
    {name:'quoteSignature',type:'bytes'}],outputs:[{name:'requestId',type:'uint256'}]},
  {type:'function',name:'route',stateMutability:'nonpayable',inputs:[{name:'proposalKey',type:'bytes32'}],outputs:[]}
];
const isAddress = x => typeof x==='string' && /^0x[0-9a-fA-F]{40}$/.test(x) && !/^0x0{40}$/.test(x);
const isBytes32 = x => typeof x==='string' && /^0x[0-9a-fA-F]{64}$/.test(x) && !/^0x0{64}$/.test(x);
const uint = (value,bits) => {
  if(typeof value==='number' && (!Number.isSafeInteger(value)||value<0))throw new Error('invalid integer');
  if(typeof value!=='number' && typeof value!=='bigint' && !(typeof value==='string' && /^(0|[1-9][0-9]*)$/.test(value)))throw new Error('invalid integer');
  const result=BigInt(value);
  if(result<0n||result>=(1n<<BigInt(bits)))throw new Error('integer out of range');
  return result;
};

export function prepareProposal({title,body,proposalKey}) {
  if(typeof title!=='string'||!title.trim()||typeof body!=='string'||!body.trim())throw new Error('title and body are required');
  if(!isBytes32(proposalKey))throw new Error('proposalKey must be bytes32');
  proposalKey=proposalKey.toLowerCase();
  const state=JSON.stringify({title,body,proposalKey});
  const stateBytes=new TextEncoder().encode(state);
  if(stateBytes.length>4096)throw new Error('proposal exceeds 4096 bytes');
  return {state,stateBytes,inputHash:keccak256(stateBytes),proposalKey};
}
export function validateQuote(quote,proposal,{router,refundTo,templateId,now=Math.floor(Date.now()/1000)}) {
  if(!isAddress(router)||!isAddress(refundTo))throw new Error('invalid address');
  if(quote.requester?.toLowerCase()!==router.toLowerCase()||quote.consumer?.toLowerCase()!==router.toLowerCase()||quote.refundTo?.toLowerCase()!==refundTo.toLowerCase())throw new Error('quote party mismatch');
  const actualTemplate=uint(quote.templateId,64);
  if(!isBytes32(quote.inputHash)||quote.inputHash.toLowerCase()!==proposal.inputHash||actualTemplate===0n||actualTemplate!==uint(templateId,64))throw new Error('quote input or template mismatch');
  const expiry=uint(quote.quoteExpiry,64), deadline=uint(quote.deadline,64), timestamp=uint(now,64);
  if(expiry<timestamp||deadline<=timestamp||expiry>deadline||deadline>timestamp+86400n)throw new Error('quote expired or deadline out of range');
  if(uint(quote.signerVersion,64)===0n)throw new Error('invalid signer version');
  uint(quote.fee,256);
  return true;
}
export async function submitProposal(wallet,{router,refundTo,templateId,quote,signature,proposal}) {
  validateQuote(quote,proposal,{router,refundTo,templateId});
  const typedQuote={...quote,templateId:BigInt(quote.templateId),deadline:BigInt(quote.deadline),
    signerVersion:BigInt(quote.signerVersion),fee:BigInt(quote.fee),quoteExpiry:BigInt(quote.quoteExpiry)};
  return wallet.writeContract({address:router,abi:routerAbi,functionName:'submit',args:[proposal.proposalKey,proposal.stateBytes,typedQuote,signature],value:BigInt(quote.fee)});
}
export const statusName = status => ['Pending','Ready','Review','Consumed','Expired'][Number(status)] ?? 'Unknown';
