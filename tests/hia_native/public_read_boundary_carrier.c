/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Qualification-only process carrier. Production ownership stays in HIA/ASM. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
typedef uint64_t U;
extern void *runtime_read_hub_create(char **,void *,void *,void *,void *);
extern long runtime_read_request_start(void *,void *,void *,size_t);
extern long runtime_read_request_poll(void *);
extern long runtime_read_request_reset(void *);
extern long runtime_read_hub_shutdown(void *);
void *view_allocate(size_t cap) {
 if (!cap || cap%4096 || cap>SIZE_MAX-4096) return (void *)-22L;
 void *p=mmap(0,cap+4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(p==MAP_FAILED)return(void *)-(long)errno;
 if(mprotect(p,cap,PROT_READ|PROT_WRITE)){long e=errno;munmap(p,cap+4096);return(void *)-e;}
 return p;
}
void *view_resize(void *old,size_t oldcap,size_t cap) {
 void *p=view_allocate(cap);if((intptr_t)p<0)return p;
 memcpy(p,old,oldcap<cap?oldcap:cap);
 if(munmap(old,oldcap+4096)){long e=errno;munmap(p,cap+4096);return(void *)-e;}
 return p;
}
static void *readfile(const char *path,size_t *size,int executable){
 int f=open(path,O_RDONLY|O_CLOEXEC);if(f<0){perror(path);exit(81);}
 struct stat st;if(fstat(f,&st)||st.st_size<=0){perror("fstat");exit(82);}
 *size=st.st_size;size_t cap=(*size+4095)&~4095ULL;void *p=view_allocate(cap);
 if((intptr_t)p<0)exit(83);
 size_t at=0;while(at<*size){ssize_t n=read(f,(char *)p+at,*size-at);if(n<=0)exit(84);at+=n;}
 close(f);if(executable&&mprotect(p,cap,PROT_READ|PROT_EXEC))exit(85);return p;
}
static U clockns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(86);return(U)t.tv_sec*1000000000+(U)t.tv_nsec;}
static void tick(void){struct timespec t={0,1000000};nanosleep(&t,0);}
int main(int argc,char **argv,char **envp){
 if(argc!=7)return 80;
 size_t l,b,w,h,q;
 void *lib=readfile(argv[1],&l,0),*boot=readfile(argv[2],&b,1),*wire=readfile(argv[3],&w,1);
 void *helper=readfile(argv[4],&h,0),*request=readfile(argv[5],&q,0);
 U *bundle=view_allocate((h+64+4095)&~4095ULL);
 if((intptr_t)bundle<0)return 87;
 memcpy(bundle,"HRRMIMG1",8);bundle[2]=h;memcpy((char *)bundle+64,helper,h);
 void *hub=runtime_read_hub_create(envp,lib,boot,wire,bundle);
 fprintf(stderr,"HUB %ld\n",(long)(intptr_t)hub);
 if((intptr_t)hub<0)return 88;
 U *ctx=view_allocate(4096);if((intptr_t)ctx<0)return 89;
 long r=runtime_read_request_start(ctx,hub,request,q);
 fprintf(stderr,"START %ld\n",r);if(r)return 90;
 char packetpath[4096]; if(snprintf(packetpath,sizeof packetpath,"%s.packet.bin",argv[6])>=4096)return 96;
 FILE *pf=fopen(packetpath,"wb");if(!pf)return 97;
 if(fwrite((char *)(uintptr_t)ctx[11]+64+ctx[18],1,ctx[19],pf)!=ctx[19])return 98;
 fclose(pf);
 U deadline=clockns()+35000000000ULL;
 while((r=runtime_read_request_poll(ctx))==1&&clockns()<deadline)tick();
 fprintf(stderr,"CAPTURE %ld %lu\n",r,(unsigned long)ctx[56]);if(r)return 91;
 int f=open(argv[6],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(f<0)return 92;
 size_t at=0;while(at<ctx[56]){ssize_t n=write(f,(char *)(uintptr_t)ctx[28]+at,ctx[56]-at);if(n<=0)return 93;at+=n;}close(f);
 r=runtime_read_request_reset(ctx);fprintf(stderr,"RESET %ld\n",r);if(r)return 94;
 r=runtime_read_hub_shutdown(hub);fprintf(stderr,"SHUTDOWN %ld\n",r);
 deadline=clockns()+35000000000ULL;
 do{r=runtime_read_hub_shutdown(hub);if(r==1)tick();}while(r==1&&clockns()<deadline);
 fprintf(stderr,"JOIN %ld\n",r);if(r)return 95;
 return 0;
}
