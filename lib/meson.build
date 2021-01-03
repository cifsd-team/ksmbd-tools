core_files = [
  'management/tree_conn.c',
  'management/user.c',
  'management/share.c',
  'management/session.c',
  'config_parser.c',
  'ksmbdtools.c',
]

if get_option('krb5')
  core_files += [
    'management/spnego.c',
    'asn1.c',
    'management/spnego_krb5.c',
  ]
endif

libksmbdtools = static_library('ksmbdtools',
  core_files,
  include_directories: tools_incdir,
  dependencies : glib_dep,
)
