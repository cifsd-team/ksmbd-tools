project('ksmbsd-tools', 'c', version: '3.3.2', default_options: 'c_std=gnu99')

tools_incdir = include_directories(['include', '.'])

glib_dep = dependency('glib-2.0')
netlink_dep = dependency('libnl-genl-3.0')
krb5_dep = dependency('krb5', required: get_option('krb5'))

cc = meson.get_compiler('c')

cdata = configuration_data()
add_project_arguments('-DHAVE_CONFIG_H', language: 'c')
if krb5_dep.found()
  cdata.set('CONFIG_KRB5', krb5_dep.found())
  cdata.set('HAVE_KRB5_KEYBLOCK_KEYVALUE', cc.has_member('krb5_keyblock', 'keyvalue', prefix: '#include <krb5.h>'))
  cdata.set('HAVE_KRB5_AUTHENTICATOR_CLIENT', cc.has_member('krb5_authenticator', 'client', prefix: '#include <krb5.h>'))
  cdata.set('HAVE_KRB5_AUTH_CON_GETRECVSUBKEY', cc.has_header_symbol('krb5.h', 'krb5_auth_con_getrecvsubkey'))
  cdata.set('HAVE_KRB5_AUTH_CON_GETAUTHENTICATOR_DOUBLE_POINTER', true)
endif
cfile = configure_file(
  output: 'config.h',
  configuration: cdata,
)

subdir('lib')
subdir('addshare')
subdir('adduser')
subdir('control')
subdir('mountd')
