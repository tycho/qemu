/*
 * Copyright (C) 2016, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PROCESSOR_H
#define QEMU_PROCESSOR_H

#if defined(HOST_X86_64)
# define cpu_relax() asm volatile("rep; nop" ::: "memory")

#elif defined(HOST_AARCH64)
# define cpu_relax() asm volatile("yield" ::: "memory")

#elif defined(__powerpc64__)
/* set Hardware Multi-Threading (HMT) priority to low; then back to medium */
# define cpu_relax() asm volatile("or 1, 1, 1;" \
                                  "or 2, 2, 2;" ::: "memory")

#else
# define cpu_relax() barrier()
#endif

#endif /* QEMU_PROCESSOR_H */
