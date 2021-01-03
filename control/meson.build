control = executable('ksmbd.control',
  'control.c',
  include_directories : tools_incdir,
  link_with : libksmbdtools,
  dependencies : [ glib_dep, netlink_dep ],
)
