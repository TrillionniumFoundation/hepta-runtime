/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Qualification child only; not a production owner or HIA result provider. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
static void all(int fd,const unsigned char *p,size_t n){
    while(n){ssize_t r=write(fd,p,n);if(r<0&&errno==EINTR)continue;if(r<=0)_exit(91);p+=r;n-=(size_t)r;}
}
static void marker(const char *root,const char *kind,unsigned slot){
    char path[4096];int n=snprintf(path,sizeof(path),"%s/%s-%u",root,kind,slot);if(n<0||(size_t)n>=sizeof(path))_exit(92);
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)_exit(93);
    uint64_t value=(uint64_t)getpid();all(fd,(unsigned char *)&value,sizeof(value));if(close(fd))_exit(94);
}
static void delay(uint64_t us){
    struct timespec t={(time_t)(us/1000000),(long)(us%1000000)*1000};
    while(nanosleep(&t,&t)&&errno==EINTR){}
}
static void pattern(int fd,uint64_t count,unsigned stream){
    unsigned char bytes[4096];uint64_t at=0;
    while(at<count){size_t n=(size_t)(count-at);if(n>sizeof(bytes))n=sizeof(bytes);
        for(size_t i=0;i<n;i++)bytes[i]=(unsigned char)(((at+i)*37+stream*29+11)&255);
        all(fd,bytes,n);at+=n;}
}
int main(int argc,char **argv){
    if(argc!=10)return 90;
    unsigned slot=(unsigned)strtoul(argv[2],0,10),behavior=(unsigned)strtoul(argv[3],0,10);
    uint64_t out=strtoull(argv[4],0,10),err=strtoull(argv[5],0,10),us=strtoull(argv[7],0,10);
    int status=(int)strtoul(argv[6],0,10);unsigned barrier=(unsigned)strtoul(argv[8],0,10);
    unsigned close_input=(unsigned)strtoul(argv[9],0,10);
    marker(argv[1],"ready",slot);
    if(barrier){char path[4096];snprintf(path,sizeof(path),"%s/release-%u",argv[1],slot);
        for(unsigned i=0;access(path,F_OK);i++){if(i==10000)return 95;delay(1000);}}
    if(close_input)close(0);
    if(us)delay(us);
    if(behavior==0){unsigned char b[3071];for(;;){ssize_t n=read(0,b,sizeof(b));if(n<0&&errno==EINTR)continue;if(n<0)return 96;if(!n)break;all(1,b,(size_t)n);}}
    else {unsigned char b[3071];if(!close_input)for(;;){ssize_t n=read(0,b,sizeof(b));if(n<0&&errno==EINTR)continue;if(n<0)return 97;if(!n)break;}
        pattern(1,out,1);}
    pattern(2,err,2);marker(argv[1],"ended",slot);return status&255;
}
