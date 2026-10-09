const MASK = (1n << 64n) - 1n;
const ROT = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const RC = [1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
const rot = (v,n) => n ? ((v << BigInt(n)) | (v >> BigInt(64-n))) & MASK : v;
export function keccak256(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  if (!(bytes instanceof Uint8Array)) throw new TypeError('expected UTF-8 string or Uint8Array');
  const data = new Uint8Array(Math.ceil((bytes.length+1)/136)*136 || 136);
  data.set(bytes); data[bytes.length]=1; data[data.length-1]|=128;
  const a=Array(25).fill(0n);
  for(let off=0;off<data.length;off+=136){
    for(let i=0;i<136;i++) a[i>>3]^=BigInt(data[off+i])<<BigInt((i&7)*8);
    for(const rc of RC){
      const c=Array.from({length:5},(_,x)=>a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20]);
      for(let x=0;x<5;x++){const d=c[(x+4)%5]^rot(c[(x+1)%5],1);for(let y=0;y<5;y++)a[x+5*y]^=d;}
      const b=Array(25).fill(0n);
      for(let x=0;x<5;x++)for(let y=0;y<5;y++)b[y+5*((2*x+3*y)%5)]=rot(a[x+5*y],ROT[x+5*y]);
      for(let x=0;x<5;x++)for(let y=0;y<5;y++)a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
      a[0]^=rc;
    }
  }
  const out=Array.from({length:32},(_,i)=>Number((a[i>>3]>>BigInt((i&7)*8))&255n));
  return '0x'+out.map(b=>b.toString(16).padStart(2,'0')).join('');
}
