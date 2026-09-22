import csv,collections,sys
tag=sys.argv[1]; lo=int(sys.argv[2]) if len(sys.argv)>2 else 7; hi=int(sys.argv[3]) if len(sys.argv)>3 else 13
rows=[r for r in csv.reader(open(f'threadcpu-{tag}.tsv'),delimiter='\t') if len(r)==5]
ts=sorted(set(float(r[0]) for r in rows))
t0=ts[lo]; t1=ts[hi]; span=t1-t0
a={}; b={}
for r in rows:
    t=float(r[0]); k=(r[1],r[2],r[3])
    if t==t0: a[k]=float(r[4])
    elif t==t1: b[k]=float(r[4])
per=collections.defaultdict(float)
for k,v in b.items():
    if k in a: per[(k[0],k[2])]+=v-a[k]
nodes=len(set(r[2] for r in rows if r[1]=='el'))
print(f'== {tag}: {span:.0f} s span, {nodes} nodes; cores per node (flood: total)')
tot=collections.defaultdict(float)
for (role,g),v in sorted(per.items(), key=lambda x:-x[1]):
    cores=v/span/(nodes if role!='flood' else 1); tot[role]+=cores
    if cores>=0.15: print(f'  {role:5} {g:26} {cores:5.2f}')
print('  totals:',' '.join(f'{r}={c:.1f}' for r,c in tot.items()))
