addshare = executable('ksmbd.addshare',
  'share_admin.c',
  'addshare.c',
  'share_admin.h',
  include_directories : tools_incdir,
  link_with : libksmbdtools,
  dependencies : [ glib_dep, netlink_dep ],
)
