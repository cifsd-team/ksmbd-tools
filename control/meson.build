control = executable(
  'ksmbd.control',
  'control.c',
  dependencies: [glib_dep, netlink_dep],
  include_directories: tools_incdir,
  link_with: libksmbdtools,
  install: true,
)
