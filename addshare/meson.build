executable(
  'ksmbd.addshare',
  'share_admin.c',
  'addshare.c',
  'share_admin.h',
  dependencies: [
    glib_dep,
    libnl_dep,
  ],
  include_directories: tools_incdir,
  link_with: libksmbdtools,
  install: true,
  install_dir: get_option('sbindir'),
  c_args: [
    '-DSYSCONFDIR="@0@"'.format(get_option('prefix') / get_option('sysconfdir')),
    '-DRUNSTATEDIR="@0@"'.format(runstatedir),
  ],
)

configure_file(
  input: 'ksmbd.addshare.8.in',
  output: 'ksmbd.addshare.8',
  install_dir: get_option('mandir') / 'man8',
  configuration: in_data,
)
