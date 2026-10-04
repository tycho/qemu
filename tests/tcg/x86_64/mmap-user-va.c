/*
 * Mappings the kernel places (no fixed address) must lie in x86_64's
 * 47-bit user address space, whatever the host's.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

#define USER_VA_END (1ull << 47)

static void check(const char *what, void *p, size_t len)
{
    uintptr_t start = (uintptr_t)p;

    if (p == MAP_FAILED || p == (void *)-1) {
        perror(what);
        exit(EXIT_FAILURE);
    }
    if (start + len > USER_VA_END) {
        fprintf(stderr, "%s: %p + 0x%zx is above the user address space\n",
                what, p, len);
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    static const size_t sizes[] = { 4096, 1 << 21, 1ul << 30 };
    void *p, *q;
    int fd, id;

    for (int i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        p = mmap(NULL, sizes[i], PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        check("mmap anonymous", p, sizes[i]);
        munmap(p, sizes[i]);
    }

    fd = open("/proc/self/exe", O_RDONLY);
    assert(fd >= 0);
    p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    check("mmap file", p, 4096);
    munmap(p, 4096);
    close(fd);

    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap before mremap", p, 4096);
    q = mremap(p, 4096, 1 << 24, MREMAP_MAYMOVE);
    check("mremap", q, 1 << 24);
    munmap(q, 1 << 24);

    id = shmget(IPC_PRIVATE, 1 << 16, IPC_CREAT | 0600);
    if (id >= 0) {
        p = shmat(id, NULL, 0);
        shmctl(id, IPC_RMID, NULL);
        check("shmat", p, 1 << 16);
        shmdt(p);
    }

    return 0;
}
