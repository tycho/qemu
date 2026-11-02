/*
 * The host's POSIX memory calls, for user-mode code
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef USER_HOST_MMAN_H
#define USER_HOST_MMAN_H

#ifdef _WIN32
/*
 * A user-mode host on Windows (windows-user) provides the calls that
 * user-mode code makes (page protection for translated code, debugger
 * access) on Windows' own.  Elsewhere they are the system's.
 */
#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4
#define MAP_FAILED ((void *)-1)

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);
ssize_t pread(int fd, void *buf, size_t n, off_t off);
ssize_t pwrite(int fd, const void *buf, size_t n, off_t off);
#endif

#endif
