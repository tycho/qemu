if not have_windows_user
   subdir_done()
endif

windows_user_ss = ss.source_set()

windows_user_ss.add(files(
  'engine.c',
  'exec.c',
  'fault.c',
  'runtime.c',
  'test.c',
  'thread.c',
  'wow64.c',
  'runtime/crt.c',
  'runtime/glib.c',
  'runtime/heap.c',
  'runtime/kernel32.c',
  'runtime/libc.c',
))

# rpmalloc, with its own configuration and its own code's warnings.
rpmalloc = static_library('rpmalloc', files('runtime/rpmalloc/rpmalloc.c'),
                          c_args: ['-DENABLE_OVERRIDE=0',
                                   '-DENABLE_DYNAMIC_LINK=0',
                                   '-DENABLE_STATISTICS=0',
                                   '-DENABLE_DECOMMIT=1',
                                   '-DENABLE_ASSERTS=0',
                                   '-fms-extensions', '-w'],
                          build_by_default: false)
windows_user_ss.add(declare_dependency(link_whole: rpmalloc))

# The C functions ntdll exports, which mingw-w64's import library leaves
# out.
ntdll_crt = custom_target('ntdll_crt',
                          input: files('runtime/ntdll-crt.def'),
                          output: 'libntdll_crt.a',
                          command: [find_program('llvm-dlltool', required: true),
                                    '-m', 'arm64', '-d', '@INPUT@',
                                    '-l', '@OUTPUT@'])

# The module's native side has ntdll alone: no C runtime or start-up
# files, and calls to other DLLs only from code the linker drops (the
# import libraries resolve them, and --gc-sections removes them with that
# code).  It sits above 4 GiB, outside the guest's address space, at a
# fixed base: in a WOW64 process the loader relocates a dynamic-base DLL
# below it.
compiler_rt = run_command(cc.cmd_array() + ['-print-libgcc-file-name'],
                          check: true).stdout().strip()
windows_user_link_args = [
  '-nostdlib',
  '-Wl,--entry=DllMainCRTStartup',
  '-Wl,--gc-sections',
  '-Wl,--image-base=0x6a00000000',
  '-Wl,--no-dynamicbase',
  '-Wl,--no-insert-timestamp',
  '-L' + meson.current_build_dir(), '-lntdll_crt',
  '-lntdll', compiler_rt, '-lmingwex',
  '-lkernel32', '-lws2_32', '-ladvapi32', '-lpathcch',
]
windows_user_link_depends = [ntdll_crt]
