import {createPublicClient,createWalletClient,custom,parseEventLogs,decodeAbiParameters} from 'https://esm.sh/viem@2.57.3';
import {keccak256,prepareProposal,submitProposal,hubAbi,routerAbi,statusName} from '../../sdk/decision-ts/index.mjs';

const el=id=>document.getElementById(id);
let prepared;
function show(message){el('message').textContent=message;}
function config(){return {router:el('router').value.trim(),hub:el('hub').value.trim(),templateId:BigInt(el('templateId').value)};}
function makeProposal(){
  const key=el('proposalKey').value.trim()||keccak256(crypto.randomUUID());
  el('proposalKey').value=key;
  prepared=prepareProposal({title:el('title').value,body:el('body').value,proposalKey:key});
  el('prepared').textContent=JSON.stringify({inputHash:prepared.inputHash,state:prepared.state},null,2);
  return prepared;
}
async function wallet(){
  if(!window.ethereum)throw new Error('请先安装 EIP-1193 钱包');
  const [account]=await window.ethereum.request({method:'eth_requestAccounts'});
  return {account,walletClient:createWalletClient({transport:custom(window.ethereum)}),publicClient:createPublicClient({transport:custom(window.ethereum)})};
}
el('prepare').onclick=()=>{try{makeProposal();show('已生成准确的 UTF-8 输入 hash。')}catch(error){show(error.message)}};
el('submit').onclick=async()=>{
  try{
    const proposal=makeProposal();
    const {quote,signature}=JSON.parse(el('quote').value);
    const {account,walletClient,publicClient}=await wallet();
    const {router,templateId}=config();
    const detail='费用 '+quote.fee+' wei；截止 '+new Date(Number(quote.deadline)*1000).toLocaleString()+'；签名者版本 '+quote.signerVersion+'。正文将公开上链。';
    if(!window.confirm(detail))return;
    const adapter={writeContract:args=>walletClient.writeContract({...args,account})};
    const hash=await submitProposal(adapter,{router,refundTo:account,templateId,quote,signature,proposal});
    show('等待提案交易入块：'+hash);
    const receipt=await publicClient.waitForTransactionReceipt({hash});
    const events=parseEventLogs({abi:routerAbi,logs:receipt.logs,eventName:'ProposalSubmitted'});
    if(events.length!==1)throw new Error('交易未包含唯一的 ProposalSubmitted 事件');
    el('requestId').value=events[0].args.requestId.toString();
    show('请求已入块，ID：'+el('requestId').value+'。等待 Relay 和 Jev 处理。');
  }catch(error){show(error.message)}
};
el('status').onclick=async()=>{
  try{
    const {publicClient}=await wallet();
    const requestId=BigInt(el('requestId').value);
    const request=await publicClient.readContract({address:config().hub,abi:hubAbi,functionName:'getRequest',args:[requestId]});
    let detail='';
    if(request.answers!=='0x'){
      const [answers]=decodeAbiParameters([{type:'tuple[]',components:[
        {name:'kind',type:'uint8'},{name:'selected',type:'uint8'},
        {name:'valuePpm',type:'uint32'},{name:'confidencePpm',type:'uint32'},
        {name:'probabilitiesPpm',type:'uint32[]'}]}],request.answers);
      const categories=['技术','社区','资金','需要补充材料'];
      detail='；分类：'+categories[Number(answers[0].selected)]+'；最高概率：'+Math.max(...answers[0].probabilitiesPpm.map(Number))/1e6+'；confidence：'+Number(answers[0].confidencePpm)/1e6;
    }
    show('状态：'+statusName(request.status)+detail+'；答案 hash：'+request.answerHash+'；证据 hash：'+request.evidenceHash);
  }catch(error){show(error.message)}
};
el('route').onclick=async()=>{
  try{
    const {account,walletClient}=await wallet();
    const hash=await walletClient.writeContract({account,address:config().router,abi:routerAbi,functionName:'route',args:[el('proposalKey').value]});
    show('分流交易：'+hash);
  }catch(error){show(error.message)}
};
