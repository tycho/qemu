/*
 * XXH3_64 known answers
 *
 * The values are xxHash 0.8.4's XXH3_64bits() of xxHash's own sanity
 * buffer (its byte generator), at lengths covering every path.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/xxh3.h"

static const struct {
    size_t len, off;
    uint64_t hash;
} xxh3_answers[] = {
    { 0, 0, 0x2d06800538d394c2ULL },
    { 1, 0, 0xc44bdff4074eecdbULL },
    { 2, 0, 0x7a9978044cb8a8bbULL },
    { 3, 0, 0x54247382a8d6b94dULL },
    { 4, 0, 0xe5dc74bc51848a51ULL },
    { 5, 0, 0xe4243f00720306bbULL },
    { 8, 0, 0x24ccc9acaa9f65e4ULL },
    { 9, 0, 0x14d5001c15dd3f2bULL },
    { 15, 0, 0x45556d4d6e1798bcULL },
    { 16, 0, 0x981b17d36c7498c9ULL },
    { 17, 0, 0x796f5acd3a60f862ULL },
    { 31, 0, 0x5d516692ca764c50ULL },
    { 32, 0, 0x9feaddbdbf57eed3ULL },
    { 33, 0, 0xabfb2d081b400a10ULL },
    { 63, 0, 0x83d74a75f2c2577aULL },
    { 64, 0, 0x9cb48487720ec49dULL },
    { 65, 0, 0xfd81aac4bebc3883ULL },
    { 96, 0, 0x935a769a7f94776fULL },
    { 97, 0, 0xca4ca268fd3c3a6cULL },
    { 127, 0, 0x2408ed71323d6096ULL },
    { 128, 0, 0xfcff24126754d861ULL },
    { 129, 0, 0x98f1b0a679a2ca29ULL },
    { 159, 0, 0x7cb32a6ecdebaf1cULL },
    { 160, 0, 0x9d03a319ed4cbd2bULL },
    { 239, 0, 0x16ce2b9d3b28805dULL },
    { 240, 0, 0x81c3c2b67f568ccfULL },
    { 241, 0, 0xc5a639ecd2030e5eULL },
    { 255, 0, 0xe98f979f4ed8a197ULL },
    { 256, 0, 0x55de574ad89d0ac5ULL },
    { 511, 0, 0x8089715b163e7fc0ULL },
    { 512, 0, 0x617e49599013cb6bULL },
    { 1023, 0, 0x87a8f7b2f2e22496ULL },
    { 1024, 0, 0xdd85c9b5c1109c5cULL },
    { 1025, 0, 0xd870c0fa13211c6aULL },
    { 2047, 0, 0xb36ece19fca2197fULL },
    { 2048, 0, 0xdd59e2c3a5f038e0ULL },
    { 2049, 0, 0xd3afa4329779b921ULL },
    { 3000, 0, 0x120a15f4cbd5a736ULL },
    { 4096, 0, 0xe91206429d1f48f9ULL },
    { 8192, 0, 0xd63690a28889a350ULL },
    { 10000, 0, 0xbcd883507019ca90ULL },
    { 7, 3, 0x7f65c880e5bb16ffULL },
    { 100, 3, 0x2c82b3793fdd9251ULL },
    { 200, 3, 0x4d92d68efb213e15ULL },
    { 777, 3, 0xa0212fd2fa7ca084ULL },
    { 1500, 3, 0x33570cd1fae3b41bULL },
};

static void test_xxh3_answers(void)
{
    g_autofree uint8_t *buf = g_malloc(10240);
    uint64_t gen = 2654435761U;

    for (size_t i = 0; i < 10240; i++) {
        buf[i] = gen >> 56;
        gen *= 11400714785074694797ULL;
    }
    for (size_t i = 0; i < ARRAY_SIZE(xxh3_answers); i++) {
        g_assert_cmphex(qemu_xxh3_64(buf + xxh3_answers[i].off,
                                     xxh3_answers[i].len),
                        ==, xxh3_answers[i].hash);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/xxh3/answers", test_xxh3_answers);
    return g_test_run();
}
