/* Mechanical resource controls for the source-pinned 19-slot view engine.
 * No HIA image executes. The sole initialization fixture returns 32;
 * successful destroy explicitly marks the private retired bit as a fixture.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

extern intptr_t view_engine_create(const uintptr_t *, uint64_t);
extern intptr_t view_allocate(uint64_t);
extern intptr_t view_resize(void *, uint64_t, uint64_t);
extern uint64_t resource_destroy_fixture(void *);
extern void resource_initialization_stub(void);
extern void resource_unexpected_stub(void);
extern uint64_t resource_stub_initializations;
extern uint64_t resource_stub_unexpected;

static const uint64_t PAGE = 4096;
static const uint64_t ENGINE_BYTES = 1807945728;
static const uint64_t capacities[19][2] = {
    {131072,16777216},
    {131072,4096},
    {131072,4096},
    {131072,4096},
    {4096,4096},
    {1056768,4096},
    {33554432,8388608},
    {33554432,8388608},
    {131072,1052672},
    {131072,16777216},
    {33554432,8388608},
    {4096,4096},
    {268435456,1048576},
    {268435456,134217728},
    {268435456,134217728},
    {268435456,134217728},
    {33554432,4096},
    {65536,172032},
    {4096,134217728},
};
struct observation {
    const char *name;
    uint64_t before, after_call, after_cleanup, mapping_bytes;
    int64_t budget, returned;
    uint64_t old_allocated, old_argument, new_capacity, offset;
    uint64_t preserved, zero_tail, explicit_cleanup_calls;
    int old_survived, old_unmapped, retired_fixture;
};

static void fail(const char *message) {
    char buffer[512];
    int n = snprintf(buffer,sizeof(buffer),"view resource control: %s (errno=%d)\n",message,errno);
    if (n > 0) {
        size_t bytes=(size_t)n < sizeof(buffer) ? (size_t)n : sizeof(buffer)-1;
        if (write(STDERR_FILENO,buffer,bytes)<0) _exit(1);
    }
    _exit(1);
}
static void require(int condition,const char *message) {
    if (!condition) fail(message);
}
static uint64_t vm_bytes(void) {
    char buffer[256];
    int fd=open("/proc/self/statm",O_RDONLY|O_CLOEXEC);
    require(fd>=0,"open statm");
    ssize_t n=read(fd,buffer,sizeof(buffer));
    int saved=errno;
    require(close(fd)==0,"close statm");
    errno=saved;
    require(n>1,"read statm");
    uint64_t pages=0;
    size_t at=0;
    while (at<(size_t)n && buffer[at]>='0' && buffer[at]<='9') {
        uint64_t digit=(uint64_t)(buffer[at]-'0');
        require(pages<=(UINT64_MAX-digit)/10,"statm overflow");
        pages=pages*10+digit;
        ++at;
    }
    require(at>0 && at<(size_t)n && buffer[at]==' ',"statm framing");
    require(pages<=UINT64_MAX/PAGE,"statm byte overflow");
    return pages*PAGE;
}
static void fill_pattern(unsigned char *p,uint64_t n) {
    for (uint64_t i=0;i<n;++i) p[i]=(unsigned char)((i*37+11)&255);
}
static void check_pattern(const unsigned char *p,uint64_t n) {
    for (uint64_t i=0;i<n;++i)
        require(p[i]==(unsigned char)((i*37+11)&255),"old bytes changed");
}
static void check_zero(const unsigned char *p,uint64_t n) {
    for (uint64_t i=0;i<n;++i) require(p[i]==0,"new tail not zero");
}
static void mapping_present(void *p) {
    unsigned char vector=0;
    require(mincore(p,PAGE,&vector)==0,"old mapping disappeared");
}
static void mapping_absent(void *p) {
    unsigned char vector=0;
    errno=0;
    require(mincore(p,PAGE,&vector)==-1 && errno==ENOMEM,"old mapping was not released");
}
static void release_map(void *p,uint64_t capacity) {
    require(munmap(p,(size_t)(capacity+PAGE))==0,"explicit mapping release");
}
static void set_limit(uint64_t ceiling,struct rlimit *saved) {
    require(getrlimit(RLIMIT_AS,saved)==0,"get RLIMIT_AS");
    require(saved->rlim_max==RLIM_INFINITY || ceiling<=saved->rlim_max,"existing hard limit too small");
    struct rlimit limited=*saved;
    limited.rlim_cur=(rlim_t)ceiling;
    require(setrlimit(RLIMIT_AS,&limited)==0,"set RLIMIT_AS");
}
static void restore_limit(const struct rlimit *saved) {
    require(setrlimit(RLIMIT_AS,saved)==0,"restore RLIMIT_AS");
}
static void image_table(uintptr_t *table) {
    table[0]=(uintptr_t)resource_initialization_stub;
    for (size_t i=1;i<19;++i) table[i]=(uintptr_t)resource_unexpected_stub;
}
static void create_destroy(struct observation *o) {
    uintptr_t table[19];
    image_table(table);
    o->before=vm_bytes();
    intptr_t result=view_engine_create(table,0);
    o->returned=(int64_t)result;
    require(result>0,"create failed");
    void *engine=(void *)(uintptr_t)result;
    o->after_call=vm_bytes();
    require(o->after_call-o->before==ENGINE_BYTES,"complete engine mapping size differs");
    uint64_t *control=(uint64_t *)engine;
    require(control[0]==(uint64_t)(uintptr_t)table,"fixed image table changed");
    require(control[2]==0 && control[3]==0 && control[4]==0 && control[12]==0,
            "initial private flags differ");
    uint64_t *descriptors=(uint64_t *)(uintptr_t)control[1];
    require(descriptors!=NULL,"descriptor table absent");
    for (size_t i=0;i<19;++i) {
        uint64_t *d=descriptors+i*8;
        require(d[0]==table[i] && d[2]==capacities[i][0] && d[4]==capacities[i][1],
                "descriptor capacity or entry differs");
        require((d[1]&4095)==0 && (d[3]&4095)==0,"mapping not page aligned");
        require(d[5]==(i==0?32U:0U) && d[6]==0 && d[7]==0,"descriptor private state differs");
    }
    require(resource_stub_initializations==1 && resource_stub_unexpected==0,"initialization stub calls differ");
    /* This mechanical fixture does not execute the HIA session lease release. */
    control[4]=1;
    o->retired_fixture=1;
    require(resource_destroy_fixture(engine)==0,"actual engine destroy failed");
    o->explicit_cleanup_calls=1;
    o->after_cleanup=vm_bytes();
    require(o->after_cleanup==o->before,"engine mappings leaked");
    o->mapping_bytes=ENGINE_BYTES;
}
static void create_enomem(struct observation *o,uint64_t budget) {
    uintptr_t table[19];
    image_table(table);
    o->before=vm_bytes();
    require(o->before<=UINT64_MAX-budget,"budget overflow");
    struct rlimit saved;
    set_limit(o->before+budget,&saved);
    intptr_t result=view_engine_create(table,0);
    o->returned=(int64_t)result;
    o->after_call=vm_bytes();
    restore_limit(&saved);
    o->after_cleanup=vm_bytes();
    require(result==-ENOMEM,"create did not return actual ENOMEM");
    require(o->after_call==o->before && o->after_cleanup==o->before,"failed create leaked a mapping");
    require(resource_stub_initializations==0 && resource_stub_unexpected==0,"failed create reached initializer");
    o->budget=(int64_t)budget;
}
static void resize_grow(struct observation *o) {
    const uint64_t old_capacity=8192,new_capacity=32768;
    o->before=vm_bytes();
    intptr_t allocated=view_allocate(old_capacity);
    require(allocated>0,"old allocation failed");
    unsigned char *old=(unsigned char *)(uintptr_t)allocated;
    fill_pattern(old,old_capacity);
    intptr_t resized=view_resize(old,old_capacity,new_capacity);
    o->returned=(int64_t)resized;
    require(resized>0 && resized!=allocated,"growth failed or aliased old mapping");
    unsigned char *current=(unsigned char *)(uintptr_t)resized;
    check_pattern(current,old_capacity);
    check_zero(current+old_capacity,new_capacity-old_capacity);
    mapping_absent(old);
    o->after_call=vm_bytes();
    require(o->after_call-o->before==new_capacity+PAGE,"growth mapping size differs");
    release_map(current,new_capacity);
    o->after_cleanup=vm_bytes();
    require(o->after_cleanup==o->before,"growth leaked mappings");
    o->mapping_bytes=new_capacity+PAGE;
    o->old_allocated=old_capacity;o->old_argument=old_capacity;o->new_capacity=new_capacity;
    o->preserved=old_capacity;o->zero_tail=new_capacity-old_capacity;o->old_unmapped=1;
    o->explicit_cleanup_calls=1;
}
static void resize_enomem(struct observation *o) {
    const uint64_t old_capacity=8192,new_capacity=32768;
    o->before=vm_bytes();
    intptr_t allocated=view_allocate(old_capacity);
    require(allocated>0,"old allocation failed");
    unsigned char *old=(unsigned char *)(uintptr_t)allocated;
    fill_pattern(old,old_capacity);
    uint64_t with_old=vm_bytes();
    require(with_old-o->before==old_capacity+PAGE,"old mapping size differs");
    struct rlimit saved;
    set_limit(with_old,&saved);
    intptr_t resized=view_resize(old,old_capacity,new_capacity);
    o->returned=(int64_t)resized;
    o->after_call=vm_bytes();
    restore_limit(&saved);
    require(resized==-ENOMEM,"resize did not return actual ENOMEM");
    mapping_present(old);mapping_present(old+PAGE);
    check_pattern(old,old_capacity);
    require(o->after_call==with_old && vm_bytes()==with_old,"failed resize changed mapping size");
    release_map(old,old_capacity);
    o->after_cleanup=vm_bytes();
    require(o->after_cleanup==o->before,"failed resize leaked mapping");
    o->mapping_bytes=old_capacity+PAGE;o->budget=0;
    o->old_allocated=old_capacity;o->old_argument=old_capacity;o->new_capacity=new_capacity;
    o->preserved=old_capacity;o->old_survived=1;o->explicit_cleanup_calls=1;
}
static void resize_unaligned(struct observation *o) {
    const uint64_t actual_capacity=8192,old_argument=4096,new_capacity=16384;
    o->before=vm_bytes();
    intptr_t allocated=view_allocate(actual_capacity);
    require(allocated>0,"old allocation failed");
    unsigned char *old=(unsigned char *)(uintptr_t)allocated;
    fill_pattern(old,actual_capacity);
    uint64_t with_old=vm_bytes();
    /* The copied 4096 bytes remain inside the actual 8192-byte old allocation.
       Only the munmap address is deliberately unaligned; no guard is read. */
    intptr_t resized=view_resize(old+1,old_argument,new_capacity);
    o->returned=(int64_t)resized;
    o->after_call=vm_bytes();
    require(resized==-EINVAL,"old unmap did not return actual EINVAL");
    mapping_present(old);mapping_present(old+PAGE);
    check_pattern(old,actual_capacity);
    require(o->after_call==with_old && with_old-o->before==actual_capacity+PAGE,
            "failed old unmap retained the new allocation or changed the old one");
    release_map(old,actual_capacity);
    o->after_cleanup=vm_bytes();
    require(o->after_cleanup==o->before,"unaligned old unmap leaked mappings");
    o->mapping_bytes=actual_capacity+PAGE;
    o->old_allocated=actual_capacity;o->old_argument=old_argument;o->new_capacity=new_capacity;
    o->offset=1;o->preserved=actual_capacity;o->old_survived=1;o->explicit_cleanup_calls=1;
}
static void publish(const struct observation *o) {
    char buffer[4096];
    int n=snprintf(buffer,sizeof(buffer),
        "{\"schema\":\"hepta.runtime.view-engine-resource-control.v1\","
        "\"status\":\"PASS\",\"control\":\"%s\","
        "\"baseline_vm_bytes\":%" PRIu64 ",\"after_call_vm_bytes\":%" PRIu64 ","
        "\"after_cleanup_vm_bytes\":%" PRIu64 ",\"mapping_bytes\":%" PRIu64 ","
        "\"budget_bytes\":%" PRId64 ",\"returned_address_or_errno\":%" PRId64 ","
        "\"old_allocated_capacity\":%" PRIu64 ",\"resize_old_capacity\":%" PRIu64 ","
        "\"resize_new_capacity\":%" PRIu64 ",\"old_pointer_offset\":%" PRIu64 ","
        "\"preserved_old_bytes\":%" PRIu64 ",\"new_zero_tail_bytes\":%" PRIu64 ","
        "\"explicit_cleanup_calls\":%" PRIu64 ","
        "\"old_mapping_survived\":%s,\"old_mapping_unmapped\":%s,"
        "\"fixture_retired_flag_written\":%s,\"initialization_stub_calls\":%" PRIu64 ","
        "\"unexpected_dispatch_calls\":%" PRIu64 ","
        "\"initialization_stub_return\":32,\"hia_semantics_executed\":false}\n",
        o->name,o->before,o->after_call,o->after_cleanup,o->mapping_bytes,o->budget,o->returned,
        o->old_allocated,o->old_argument,o->new_capacity,o->offset,o->preserved,o->zero_tail,
        o->explicit_cleanup_calls,o->old_survived?"true":"false",o->old_unmapped?"true":"false",
        o->retired_fixture?"true":"false",resource_stub_initializations,resource_stub_unexpected);
    require(n>0 && (size_t)n<sizeof(buffer),"output overflow");
    size_t at=0;
    while (at<(size_t)n) {
        ssize_t wrote=write(STDOUT_FILENO,buffer+at,(size_t)n-at);
        if (wrote<0 && errno==EINTR) continue;
        require(wrote>0,"output write failed");at+=(size_t)wrote;
    }
}
int main(int argc,char **argv) {
    require(argc>=2 && argc<=3,"arguments");
    require(sysconf(_SC_PAGESIZE)==4096,"unsupported page size");
    struct rlimit primed;
    require(getrlimit(RLIMIT_AS,&primed)==0,"prime rlimit");
    require(vm_bytes()==vm_bytes(),"VM changed during baseline priming");
    struct observation o={0};
    o.name=argv[1];o.budget=-1;
    if (!strcmp(argv[1],"create-destroy") && argc==2) create_destroy(&o);
    else if (!strcmp(argv[1],"create-enomem") && argc==3) {
        static const char *allowed[]={"0","16384","262144","20971520","67108864","134217728","536870912","1610612736"};
        size_t i=0;
        for (;i<sizeof(allowed)/sizeof(allowed[0]);++i) if (!strcmp(argv[2],allowed[i])) break;
        require(i<sizeof(allowed)/sizeof(allowed[0]),"unknown budget");
        char *end=NULL;errno=0;
        uint64_t budget=strtoull(argv[2],&end,10);
        require(errno==0 && end && !*end,"invalid budget");
        create_enomem(&o,budget);
    } else if (!strcmp(argv[1],"resize-grow") && argc==2) resize_grow(&o);
    else if (!strcmp(argv[1],"resize-enomem") && argc==2) resize_enomem(&o);
    else if (!strcmp(argv[1],"resize-unaligned-old") && argc==2) resize_unaligned(&o);
    else fail("unknown control");
    require(resource_stub_unexpected==0,"unexpected HIA dispatcher use");
    publish(&o);
    return 0;
}
