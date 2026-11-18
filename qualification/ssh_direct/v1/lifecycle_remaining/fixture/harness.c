/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Qualification embedding only. All production behavior is in frozen HIA+ASM. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
extern void *ssh_direct_start(void(*)(void*,const void*,uint64_t),void*);
extern void *ssh_direct_submit(void*,const void*,uint64_t,const void*,uint64_t,const void*);
extern long ssh_direct_cancel(void*);
extern long ssh_direct_result(void*,void*);
extern long ssh_direct_capture_result(void*,void*);
extern void ssh_direct_request_release(void*);
extern long ssh_direct_shutdown(void*);
extern long ssh_direct_join_result(void*);
extern long ssh_direct_freeze(void);
typedef struct {uint64_t word[12];} Result;
typedef struct {
    uint64_t deadline_lo,deadline_hi;
    uint64_t(*enter)(void*,void**);void *opaque;void(*guard_drop)(void*);void(*entry_drop)(void*);
    uint64_t zero[2];
} Options;
typedef struct {
    uint64_t spec[16];unsigned char *input;char root[4096],child[4096];
    int journal;atomic_flag output_lock;atomic_uint gate_reached,gate_release,gate_claimed;
    atomic_ulong entered,dropped,entry_discarded,live,entry_tid,caller_tid;
    void *context;Result results[64];void *requests[64];uint64_t complete[64];
    uint64_t live_when_caller_gone,join_pending_before_release,ready_peak;
} State;
static long sc6(long n,long a,long b,long c,long d,long e,long f){
    register long r10 __asm__("r10")=d;register long r8 __asm__("r8")=e;register long r9 __asm__("r9")=f;
    long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
static void raw_all(int fd,const unsigned char *p,uint64_t n){
    while(n){long r=sc6(1,fd,(long)p,(long)n,0,0,0);if(r==-4)continue;if(r<=0){sc6(231,99,0,0,0,0,0);__builtin_unreachable();}p+=r;n-=r;}
}
static void notify(atomic_uint *word){sc6(202,(long)word,129,2147483647,0,0,0);}
static void park(atomic_uint *word){while(!atomic_load_explicit(word,memory_order_acquire))sc6(202,(long)word,128,0,0,0,0);}
static void observe(void *opaque,const void *data,uint64_t bytes){
    State *s=opaque;const uint64_t *p=data;
    while(atomic_flag_test_and_set_explicit(&s->output_lock,memory_order_acquire))__asm__ volatile("pause");
    raw_all(s->journal,data,bytes);
    atomic_flag_clear_explicit(&s->output_lock,memory_order_release);
    const uint64_t *in=(const uint64_t *)((const unsigned char*)data+128);
    int selected=(s->spec[2]==2&&p[6]==1&&in[1]==4&&p[9]==320)
        ||(s->spec[2]==3&&p[6]==2&&in[1]==7&&p[9]==576);
    if(selected&&atomic_exchange_explicit(&s->gate_claimed,1,memory_order_acq_rel)==0){
        atomic_store_explicit(&s->gate_reached,1,memory_order_release);notify(&s->gate_reached);park(&s->gate_release);
    }
}
static uint64_t entry(void *opaque,void **guard){
    State *s=opaque;atomic_fetch_add(&s->entered,1);
    atomic_store(&s->entry_tid,(unsigned long)sc6(186,0,0,0,0,0,0));
    if(s->spec[6]==2)return 17;
    atomic_fetch_add(&s->live,1);*guard=s;return 0;
}
static void guard_drop(void *opaque){State *s=opaque;atomic_fetch_add(&s->dropped,1);atomic_fetch_sub(&s->live,1);}
static void unused_drop(void *opaque){State *s=opaque;atomic_fetch_add(&s->entry_discarded,1);}
static void die(const char *msg){perror(msg);exit(98);}
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))die("clock");return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
static void pause_ms(void){struct timespec t={0,1000000};nanosleep(&t,0);}
static void path(char *out,size_t n,State *s,const char *base,unsigned index){
    int r=snprintf(out,n,"%s/%s-%u",s->root,base,index);if(r<0||(size_t)r>=n)die("path");}
static void named(char *out,size_t n,State *s,const char *base){
    int r=snprintf(out,n,"%s/%s",s->root,base);if(r<0||(size_t)r>=n)die("named path");}
static void file(const char *name,const void *bytes,size_t count){int fd=open(name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)die("open output");raw_all(fd,bytes,count);if(close(fd))die("close output");}
static int exists(State *s,const char *base,unsigned slot){char p[4096];path(p,sizeof(p),s,base,slot);return access(p,F_OK)==0;}
static void wait_all_ready(State *s,unsigned count){uint64_t end=now_ns()+10000000000ULL;
    for(;;){unsigned n=0;for(unsigned i=0;i<count;i++)n+=exists(s,"ready",i);if(n>s->ready_peak)s->ready_peak=n;if(n==count)return;if(now_ns()>=end)die("children readiness");pause_ms();}}
static void release_children(State *s,unsigned count){for(unsigned i=0;i<count;i++){char p[4096];path(p,sizeof(p),s,"release",i);file(p,"release",7);}}
static void *command(State *s,unsigned slot,uint64_t *length){
    char words[8][32];const char *args[10];const char *executable=s->spec[2]==5?"/hepta-ssh-frozen-domain-no-such-executable":s->child;
    args[0]=executable;args[1]=s->root;
    uint64_t values[8]={slot,s->spec[12],s->spec[8],s->spec[9],s->spec[10],s->spec[11],s->spec[2]==1,s->spec[13]};
    for(unsigned i=0;i<8;i++){snprintf(words[i],sizeof(words[i]),"%lu",(unsigned long)values[i]);args[i+2]=words[i];}
    uint64_t n=65+strlen(executable);for(unsigned i=0;i<10;i++)n+=9+strlen(args[i]);
    unsigned char *b=calloc(1,n);if(!b)die("command allocation");memcpy(b,"HSDCMD01",8);
    uint64_t *h=(uint64_t*)b;h[1]=strlen(executable);h[2]=10;h[3]=0;h[4]=s->spec[5];h[5]=n;
    memcpy(b+64,executable,strlen(executable));uint64_t at=65+strlen(executable);
    for(unsigned i=0;i<10;i++){uint64_t size=strlen(args[i]);memcpy(b+at,&size,8);at+=8;memcpy(b+at,args[i],size);at+=size+1;}
    if(at!=n)die("command extent");
    *length=n;
    return b;
}
static void submit(State *s,unsigned i){
    uint64_t n;void *cmd=command(s,i,&n);Options o={0};
    o.deadline_lo=now_ns()+s->spec[4]*1000000;
    if(s->spec[6]){o.enter=entry;o.opaque=s;o.guard_drop=guard_drop;o.entry_drop=unused_drop;}
    s->requests[i]=ssh_direct_submit(s->context,cmd,n,s->input,s->spec[7],&o);free(cmd);
    if((intptr_t)s->requests[i]<=0)die("native submit");
}
static void settle(State *s,unsigned i,int raw){
    uint64_t end=now_ns()+55000000000ULL;
    for(;;){long r=raw?ssh_direct_result(s->requests[i],&s->results[i]):ssh_direct_capture_result(s->requests[i],&s->results[i]);
        if(r==0){s->complete[i]=1;return;}if(r!=1||now_ns()>=end)die("native result");pause_ms();}
}
static void save_result(State *s,unsigned i){
    Result *r=&s->results[i];char p[4096];path(p,sizeof(p),s,"stdout",i);file(p,(void*)(uintptr_t)r->word[6],(size_t)r->word[7]);
    path(p,sizeof(p),s,"stderr",i);file(p,(void*)(uintptr_t)r->word[8],(size_t)r->word[9]);
    Result value=*r;value.word[6]=0;value.word[8]=0;path(p,sizeof(p),s,"RESULT",i);file(p,&value,sizeof(value));
}
static void *vanishing_caller(void *opaque){
    State *s=opaque;atomic_store(&s->caller_tid,(unsigned long)sc6(186,0,0,0,0,0,0));
    submit(s,0);settle(s,0,0);save_result(s,0);ssh_direct_request_release(s->requests[0]);s->requests[0]=0;return 0;
}
static void join_owner(State *s,long initial){
    uint64_t end=now_ns()+10000000000ULL;long value=initial;
    while(value==1){if(now_ns()>=end)die("original join");pause_ms();value=ssh_direct_join_result(s->context);}
    if(value)die("original join error");
}
int main(int argc,char **argv){
    if(argc!=4)return 90;
    State *s=calloc(1,sizeof(*s));if(!s)die("state");atomic_flag_clear(&s->output_lock);
    if(strlen(argv[2])>=sizeof(s->root)||strlen(argv[3])>=sizeof(s->child))return 91;
    strcpy(s->root,argv[2]);strcpy(s->child,argv[3]);
    int fd=open(argv[1],O_RDONLY|O_CLOEXEC);if(fd<0)die("case open");
    if(read(fd,s->spec,sizeof(s->spec))!=(ssize_t)sizeof(s->spec)||memcmp(s->spec,"HSSCASE1",8))return 92;
    if(s->spec[3]==0||s->spec[3]>64||s->spec[7]>(16U<<20))return 93;
    s->input=malloc(s->spec[7]?s->spec[7]:1);uint64_t at=0;while(at<s->spec[7]){ssize_t n=read(fd,s->input+at,s->spec[7]-at);if(n<=0)die("case input");at+=n;}unsigned char extra;if(read(fd,&extra,1)!=0)return 94;close(fd);
    char name[4096];named(name,sizeof(name),s,"HIA-JOURNAL.bin");s->journal=open(name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(s->journal<0)die("journal open");
    s->context=ssh_direct_start(observe,s);if((intptr_t)s->context<=0)die("owner start");
    unsigned count=(unsigned)s->spec[3];uint64_t mode=s->spec[2];long started_join=1;
    if(mode==3){
        pthread_t caller;if(pthread_create(&caller,0,vanishing_caller,s))die("caller thread");
        if(pthread_join(caller,0))die("caller exit");
        park(&s->gate_reached);s->live_when_caller_gone=atomic_load(&s->live);
        started_join=ssh_direct_shutdown(s->context);s->join_pending_before_release=started_join==1;
        atomic_store_explicit(&s->gate_release,1,memory_order_release);notify(&s->gate_release);
    }else{
        atomic_store(&s->caller_tid,(unsigned long)sc6(186,0,0,0,0,0,0));
        for(unsigned i=0;i<count;i++)submit(s,i);
        if(mode==1){wait_all_ready(s,count);release_children(s,count);}
        if(mode==2){park(&s->gate_reached);if(ssh_direct_cancel(s->requests[0]))die("cancel");
            atomic_store_explicit(&s->gate_release,1,memory_order_release);notify(&s->gate_release);}
        for(unsigned i=0;i<count;i++){settle(s,i,mode==2);save_result(s,i);ssh_direct_request_release(s->requests[i]);s->requests[i]=0;}
        started_join=ssh_direct_shutdown(s->context);
    }
    join_owner(s,started_join);
    uint64_t *c=s->context;uint64_t report[24]={0};memcpy(report,"HSSRUN01",8);
    report[1]=s->spec[1];report[2]=mode;report[3]=count;report[4]=atomic_load(&s->entered);
    report[5]=atomic_load(&s->dropped);report[6]=atomic_load(&s->live);report[7]=atomic_load(&s->entry_discarded);
    report[8]=c[216/8];report[9]=c[224/8];report[10]=c[200/8];report[11]=c[208/8];
    report[12]=atomic_load(&s->entry_tid);report[13]=atomic_load(&s->caller_tid);report[14]=s->live_when_caller_gone;
    report[15]=s->join_pending_before_release;report[16]=s->ready_peak;report[17]=c[48/8];report[18]=c[144/8];report[19]=c[152/8];
    report[20]=c[904/8];report[21]=c[112/8];report[22]=c[896/8];
    named(name,sizeof(name),s,"RUN.bin");file(name,report,sizeof(report));
    uint64_t *work=(uint64_t*)(uintptr_t)c[(256+24)/8];uint64_t extent=c[(256+32)/8];
    named(name,sizeof(name),s,"CORE-WORK.bin");file(name,work,extent);
    if(close(s->journal))die("journal close");
    if(report[6]||report[17]||report[18]!=1||report[19]!=1||report[20]!=1||report[21]||report[22]||report[10]!=report[11])return 95;
    return 0;
}
