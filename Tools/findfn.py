import sys, re
sys.path.insert(0,'/home/abzal/ios262_lab/spmt/ana')
import macho
from sptm import INS, func_of, adrp_page
m = macho.MachO('/home/abzal/ios262_lab/spmt/sptm.macho')
HEX=re.compile(r'#(0x[0-9a-f]+)')
def cstrs():
    out={}
    for seg in m.segments:
        for sec in seg['sections']:
            if sec['name']=='__cstring':
                base=sec['addr']; data=m.d[sec['off']:sec['off']+sec['size']]
                i=0
                while i<len(data):
                    j=data.find(b'\0',i)
                    if j<0: break
                    s=data[i:j].decode('utf-8','replace')
                    if len(s)>=2: out[base+i]=s
                    i=j+1
    return out
C=cstrs()
def refs(t):
    hits=[]
    for i,ins in enumerate(INS):
        if ins.mnemonic!='adrp': continue
        mm=HEX.search(ins.op_str)
        if not mm: continue
        page=int(mm.group(1),16)
        if page!=(t & ~0xfff): continue
        dst=ins.op_str.split(',')[0].strip()
        for j in range(i+1,min(i+12,len(INS))):
            i2=INS[j]
            if i2.mnemonic=='add':
                p=[x.strip() for x in i2.op_str.split(',')]
                if len(p)==3 and p[1]==dst:
                    m2=HEX.search(p[2])
                    if m2 and page+int(m2.group(1),16)==t:
                        hits.append((i2.address, func_of(i2.address))); break
            if i2.mnemonic in ('b','bl','ret','br','blr','cbz','cbnz','tbz','tbnz','b.eq','b.ne','svc'): break
    return hits
if __name__=='__main__':
    for name in sys.argv[1:]:
        t=[va for va,s in C.items() if s==name]
        if not t: print(name,'NOT FOUND'); continue
        t=t[0]
        print(f'--- {name} @ {t:#x} ---')
        for a,f in refs(t): print(f'   ref {a:#x} func {f and hex(f)}')
