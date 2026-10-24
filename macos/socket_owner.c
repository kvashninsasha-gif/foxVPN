/* Same-user fallback: macOS hides other processes from unprivileged pcblist.
 * Inspect kernel socket descriptors, never user supplied PIDs or filenames.
 * Bounded work, exact TCP tuples, unconnected UDP only, ambiguity fails closed. */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
static uint64_t fox_owner_now(void) {
    struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000000000ull+(uint64_t)t.tv_nsec;
}
int fox_user_connection_owner(uint8_t network, uint8_t family, const uint8_t *source,
                              const uint8_t *destination, uint16_t source_port, uint16_t destination_port) {
    if((network!=1&&network!=2)||(family!=4&&family!=6)||!source_port) return 0;
    int pids[4096]; int n=proc_listpids(PROC_UID_ONLY,geteuid(),pids,sizeof(pids));
    if(n<=0||n>=(int)sizeof(pids)) return 0;
    uint64_t started=fox_owner_now(); unsigned calls=0; int exact=0,fallback=0;
    for(int i=0;i<n/(int)sizeof(int);i++) {
        if(pids[i]<2) continue;
        struct proc_fdinfo fds[4096];
        int bytes=proc_pidinfo(pids[i],PROC_PIDLISTFDS,0,fds,sizeof(fds));
        if(bytes<0) continue;
        if(bytes>=(int)sizeof(fds)) return 0;
        for(int j=0;j<bytes/(int)sizeof(struct proc_fdinfo);j++) {
            if(fox_owner_now()-started>200000000ull||++calls>32768) return 0;
            if(fds[j].proc_fdtype!=PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo info; memset(&info,0,sizeof(info));
            if(proc_pidfdinfo(pids[i],fds[j].proc_fd,PROC_PIDFDSOCKETINFO,&info,sizeof(info))!=(int)sizeof(info)) continue;
            const struct in_sockinfo *ip;
            if(network==1&&info.psi.soi_kind==SOCKINFO_TCP) ip=&info.psi.soi_proto.pri_tcp.tcpsi_ini;
            else if(network==2&&info.psi.soi_kind==SOCKINFO_IN&&info.psi.soi_protocol==IPPROTO_UDP) ip=&info.psi.soi_proto.pri_in;
            else continue;
            if(ntohs((uint16_t)ip->insi_lport)!=source_port) continue;
            if((family==4&&!(ip->insi_vflag&INI_IPV4))||(family==6&&!(ip->insi_vflag&INI_IPV6))) continue;
            int offset=family==4?12:0,length=family==4?4:16;
            const uint8_t *local=((const uint8_t*)&ip->insi_laddr)+offset;
            const uint8_t *remote=((const uint8_t*)&ip->insi_faddr)+offset;
            if(!memcmp(local,source,length)&&ntohs((uint16_t)ip->insi_fport)==destination_port&&!memcmp(remote,destination,length)) {
                if(exact&&exact!=pids[i]) return 0; exact=pids[i];
            } else if(network==2&&!ip->insi_fport) {
                uint8_t zero[16]={0};
                if(!memcmp(remote,zero,length)&&(!memcmp(local,source,length)||!memcmp(local,zero,length))) {
                    if(fallback&&fallback!=pids[i]) fallback=-1; else if(!fallback) fallback=pids[i];
                }
            }
        }
    }
    return exact>0?exact:(fallback>0?fallback:0);
}
