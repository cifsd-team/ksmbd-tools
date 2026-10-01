quota_test = executable(
  'quota-test',
  'quota.c',
  '../mountd/quota.c',
  include_directories: include_dirs,
  dependencies: glib_dep,
  link_args: [
    '-Wl,--wrap=open,--wrap=open64,--wrap=close,--wrap=fstat,--wrap=fstat64,--wrap=fstatfs,--wrap=fstatfs64,--wrap=syscall,--wrap=ioctl',
  ],
)
test('quota', quota_test)
