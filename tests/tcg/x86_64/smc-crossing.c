/*
 * Self-modifying code through an access that crosses 16 bytes.
 *
 * Each copy of a small function XORs, with one 8-byte read-modify-write
 * that crosses a 16-byte boundary, the immediate of a "mov eax, imm32"
 * further on in the same function, then runs it.  The function must return
 * the new immediate.  A second thread exists so that guest accesses are
 * ordered (x-tso), where such an access takes its out-of-line path.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define COPIES 4096
#define STRIDE 64
/* The function starts 6 bytes past a 16-byte boundary. */
#define SKEW 6

/*
 *    0: 48 b9 <key>               movabs rcx, key
 *   10: 48 31 0d 03 00 00 00      xor [rip + 3], rcx   (bytes 20-27)
 *   17: 90 90 90                  nop
 *   20: b8 <imm32>                mov eax, imm32
 *   25: 90 90 90                  nop
 *   28: c3                        ret
 *
 * Bytes 20-27 are at boundary + 26 to + 33: they cross + 32.  The key
 * changes only bytes 21-24, the immediate.
 */
static void emit(uint8_t *p, uint32_t old_imm, uint32_t new_imm)
{
    static const uint8_t head[] = { 0x48, 0xb9 };
    static const uint8_t mid[] = { 0x48, 0x31, 0x0d, 0x03, 0x00, 0x00, 0x00,
                                   0x90, 0x90, 0x90, 0xb8 };
    static const uint8_t tail[] = { 0x90, 0x90, 0x90, 0xc3 };
    uint64_t key = (uint64_t)(old_imm ^ new_imm) << 8;

    memcpy(p, head, sizeof(head));
    memcpy(p + 2, &key, 8);
    memcpy(p + 10, mid, sizeof(mid));
    memcpy(p + 21, &old_imm, 4);
    memcpy(p + 25, tail, sizeof(tail));
}

static void *idle(void *arg)
{
    for (;;) {
        pause();
    }
    return arg;
}

int main(void)
{
    pthread_t th;
    uint8_t *m = mmap(NULL, COPIES * STRIDE,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int bad = 0;

    if (m == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    pthread_create(&th, NULL, idle, NULL);
    for (int i = 0; i < COPIES; i++) {
        uint8_t *f = m + i * STRIDE + SKEW;
        uint32_t old_imm = 0x10000000u + i, new_imm = 0x20000000u + i;
        uint32_t got;

        emit(f, old_imm, new_imm);
        got = ((uint32_t (*)(void))f)();
        if (got != new_imm && bad++ < 5) {
            fprintf(stderr, "copy %d returned %08x, expected %08x\n",
                    i, got, new_imm);
        }
    }
    if (bad) {
        fprintf(stderr, "%d of %d copies ran the old code\n", bad, COPIES);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
