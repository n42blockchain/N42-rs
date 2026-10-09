export type Hex = string;
export interface Quote { requester: Hex; refundTo: Hex; consumer: Hex; templateId: bigint|string|number; inputHash: Hex; deadline: bigint|string|number; signerVersion: bigint|string|number; fee: bigint|string|number; quoteExpiry: bigint|string|number }
export interface Proposal { state:string; stateBytes:Uint8Array; inputHash:Hex; proposalKey:Hex }
export declare function keccak256(input:string|Uint8Array):Hex;
export declare const quoteComponents:readonly object[];
export declare const hubAbi:readonly object[];
export declare const routerAbi:readonly object[];
export declare function prepareProposal(input:{title:string;body:string;proposalKey:Hex}):Proposal;
export declare function validateQuote(quote:Quote,proposal:Proposal,context:{router:Hex;refundTo:Hex;templateId:bigint|string|number;now?:number}):true;
export declare function submitProposal(wallet:{writeContract(args:object):Promise<Hex>},input:{router:Hex;refundTo:Hex;templateId:bigint|string|number;quote:Quote;signature:Hex;proposal:Proposal}):Promise<Hex>;
export declare function statusName(status:number|bigint):string;
