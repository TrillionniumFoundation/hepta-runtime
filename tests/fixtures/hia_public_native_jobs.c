/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * External qualification workload; never an installed HIA runtime member. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int number(const char *text, uintmax_t *out) {
    char *end;
    if (!text || !*text || *text == '-') return 0;
    errno = 0;
    *out = strtoumax(text, &end, 10);
    return !errno && !*end;
}

static int output(int fd, const unsigned char *data, size_t size) {
    while (size) {
        ssize_t used = write(fd, data, size);
        if (used < 0 && errno == EINTR) continue;
        if (used <= 0) return 0;
        data += used;
        size -= (size_t)used;
    }
    return 1;
}

static int pattern(int fd, size_t size, unsigned multiplier, unsigned addend) {
    unsigned char block[4096];
    size_t offset = 0;
    while (offset < size) {
        size_t count = size - offset;
        if (count > sizeof(block)) count = sizeof(block);
        for (size_t i = 0; i < count; ++i)
            block[i] = (unsigned char)((offset + i) * multiplier + addend);
        if (!output(fd, block, count)) return 0;
        offset += count;
    }
    return 1;
}

int main(int argc, char **argv) {
    uintmax_t descriptor, device, inode;
    struct stat info;
    unsigned char header[7];
    const char *selected = getenv("HIA_PUBLIC_EXPECTED_ARGV0");
    if (argc < 4 || !selected || strcmp(argv[0], selected)) return 94;
    if (!number(argv[2], &device) || !number(argv[3], &inode) ||
        !number(getenv("HEPTA_RUNTIME_WORKER_ENTRY_FD"), &descriptor) || descriptor > INT_MAX)
        return 91;
    int fd = (int)descriptor;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        (uintmax_t)info.st_dev != device || (uintmax_t)info.st_ino != inode ||
        pread(fd, header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        memcmp(header, "\177ELF\002\001\001", sizeof(header))) return 92;
    if (!strcmp(argv[1], "streams")) {
        static const unsigned char expected[] = "public-native-stdin\n";
        unsigned char input[sizeof(expected)];
        size_t used = 0;
        while (used < sizeof(input)) {
            ssize_t count = read(STDIN_FILENO, input + used, sizeof(input) - used);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) return 95;
            if (!count) break;
            used += (size_t)count;
        }
        if (used != sizeof(expected) - 1 || memcmp(input, expected, used)) return 96;
        if (!pattern(STDOUT_FILENO, 131109, 13, 7) ||
            !pattern(STDERR_FILENO, 8193, 3, 11)) return 93;
        return 17;
    }
    if (!strcmp(argv[1], "cancel")) {
        if (!output(STDOUT_FILENO, (const unsigned char *)"ready\n", 6)) return 93;
        for (;;) pause();
    }
    if (!strcmp(argv[1], "marker") && argc == 5) {
        int marker = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (marker < 0) return 97;
        int ok = output(marker, (const unsigned char *)"unexpected-execution\n", 21);
        if (close(marker)) return 98;
        return ok ? 0 : 93;
    }
    return 99;
}
