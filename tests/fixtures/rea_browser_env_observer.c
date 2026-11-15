/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test-only observation in the actual Chrome ELF before main. This does not
 * set any environment variable, replace the launcher, or attest another PID.
 * Only the original session leader is observed; unrelated values are omitted.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef REA_OBSERVER_EXECUTABLE
#error "An independently pinned Chrome executable is required"
#endif
#ifndef REA_OBSERVER_DIRECTORY
#error "A private observation directory is required"
#endif
#ifndef REA_OBSERVER_EXIT_AFTER_RECORD
#define REA_OBSERVER_EXIT_AFTER_RECORD 0
#endif

extern char **environ;
static char output[65536];
static size_t used;

static void fail(void) { _exit(125); }

static void append(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int count = vsnprintf(output + used, sizeof(output) - used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= sizeof(output) - used) fail();
    used += (size_t)count;
}

static void hexadecimal(const char *value) {
    if (!value) { append("null"); return; }
    size_t size = strnlen(value, 4097);
    if (size > 4096) fail();
    append("\"");
    for (size_t i = 0; i < size; ++i) append("%02x", (unsigned char)value[i]);
    append("\"");
}

static void read_stat(char *buffer, size_t capacity) {
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail();
    ssize_t size = read(fd, buffer, capacity - 1);
    if (size <= 0 || (size_t)size == capacity - 1) fail();
    buffer[size] = 0;
    if (close(fd)) fail();
}

static uint64_t start_ticks(void) {
    char buffer[16384];
    read_stat(buffer, sizeof(buffer));
    char *last = strrchr(buffer, ')'), *save = NULL;
    if (!last) fail();
    char *part = strtok_r(last + 1, " ", &save);
    for (int field = 3; part; ++field, part = strtok_r(NULL, " ", &save)) {
        if (field == 22) {
            char *end = NULL;
            errno = 0;
            unsigned long long value = strtoull(part, &end, 10);
            if (errno || !end || *end || !value) fail();
            return (uint64_t)value;
        }
    }
    fail();
    return 0;
}

__attribute__((constructor))
static void observe_original_chrome(void) {
    char executable[4097];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length <= 0 || (size_t)length == sizeof(executable) - 1) fail();
    executable[length] = 0;
    if (strcmp(executable, REA_OBSERVER_EXECUTABLE) || getpid() != getpgrp()) return;

    int exe = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    struct stat version;
    if (exe < 0 || fstat(exe, &version) || !S_ISREG(version.st_mode)) fail();
    if (close(exe)) fail();
    uint64_t ticks = start_ticks();
    static const char *keys[] = {"HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"};
    unsigned counts[4] = {0, 0, 0, 0};
    size_t environment_size = 0, count = 0;
    for (; count < 16384 && environ[count]; ++count) {
        size_t size = strnlen(environ[count], 1048577);
        if (size > 1048576 || size + 1 > 1048576 - environment_size) fail();
        environment_size += size + 1;
        for (size_t k = 0; k < 4; ++k) {
            size_t key_size = strlen(keys[k]);
            if (size > key_size && !memcmp(environ[count], keys[k], key_size)
                && environ[count][key_size] == '=') ++counts[k];
        }
    }
    if (count == 16384) fail();

    append("{\"schema\":\"hepta.rea.chrome-exec-environment.v1\","
           "\"phase\":\"actual_chrome_elf_constructor_before_main\","
           "\"pid\":%jd,\"parent_pid\":%jd,\"pgid\":%jd,\"start_ticks\":%" PRIu64 ",",
           (intmax_t)getpid(), (intmax_t)getppid(), (intmax_t)getpgrp(), ticks);
    append("\"executable\":{\"device\":%ju,\"inode\":%ju,\"size\":%ju,"
           "\"mode\":%ju,\"uid\":%ju,\"gid\":%ju,\"links\":%ju,"
           "\"mtime_ns\":%ju,\"ctime_ns\":%ju},",
           (uintmax_t)version.st_dev, (uintmax_t)version.st_ino,
           (uintmax_t)version.st_size, (uintmax_t)version.st_mode,
           (uintmax_t)version.st_uid, (uintmax_t)version.st_gid,
           (uintmax_t)version.st_nlink,
           (uintmax_t)version.st_mtim.tv_sec * 1000000000U + (uintmax_t)version.st_mtim.tv_nsec,
           (uintmax_t)version.st_ctim.tv_sec * 1000000000U + (uintmax_t)version.st_ctim.tv_nsec);
    append("\"environment_hex\":{");
    for (size_t k = 0; k < 4; ++k) {
        append("%s\"%s\":", k ? "," : "", keys[k]);
        hexadecimal(getenv(keys[k]));
    }
    append("},\"key_counts\":{");
    for (size_t k = 0; k < 4; ++k)
        append("%s\"%s\":%u", k ? "," : "", keys[k], counts[k]);
    append("},\"negative_control_exit_before_main\":%s}\n",
           REA_OBSERVER_EXIT_AFTER_RECORD ? "true" : "false");

    int directory = open(REA_OBSERVER_DIRECTORY, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat parent;
    if (directory < 0 || fstat(directory, &parent) || parent.st_uid != getuid()
        || (parent.st_mode & 0777) != 0700) fail();
    char name[128];
    int name_size = snprintf(name, sizeof(name), "chrome-%jd-%" PRIu64 ".json",
                             (intmax_t)getpid(), ticks);
    if (name_size <= 0 || (size_t)name_size >= sizeof(name)) fail();
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail();
    size_t offset = 0;
    while (offset < used) {
        ssize_t amount = write(fd, output + offset, used - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) fail();
        offset += (size_t)amount;
    }
    if (fsync(fd) || close(fd) || fsync(directory) || close(directory)) fail();
    if (REA_OBSERVER_EXIT_AFTER_RECORD) _exit(0);
}
