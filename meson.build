project('ksmbsd-tools', 'c',
  version : '3.3.2',
  default_options : 'c_std=gnu99',
)

tools_incdir = include_directories(['include', '.'])

if get_option('krb5')
  add_global_arguments('-DCONFIG_KRB5', language : 'c')
endif

glib_dep = dependency('glib-2.0')
netlink_dep = dependency('libnl-genl-3.0')
if get_option('krb5')
  krb5_dep = dependency('krb5')
endif

subdir('lib')
subdir('addshare')
subdir('adduser')
subdir('control')
subdir('mountd')
