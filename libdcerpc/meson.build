# libdcerpc, a copy of libsmb2's libdcerpc/ (see README.ksmbd-tools):
# the coders and the server runtime without the libsmb2 transport,
# linked statically into ksmbd.tools. Nothing is installed.

python3 = find_program('python3')
idlcomp = files('idlcomp.py')

# Interfaces whose coders and public header dcerpc/<iface>.h are
# generated from <iface>/<iface>.idl at build time.
dcerpc_ifaces = [
  'srvsvc',
  'wkssvc',
  'winreg',
  'lsa',
  'samr',
  'dssetup',
  'netlogon',
  'epm',
]
dcerpc_idls = {}
foreach iface : dcerpc_ifaces
  dcerpc_idls += {iface: files(iface + '/' + iface + '.idl')}
endforeach

# The generated files go next to the hand-written headers, in the build
# tree, so that <dcerpc/iface.h> resolves through the one include
# directory. Sets dcerpc_coders and dcerpc_headers.
subdir('include/dcerpc')

libdcerpc_inc = include_directories('include')

libdcerpc_lib = static_library(
  'dcerpc',
  'dcerpc.c',
  'dcerpc-dtyp.c',
  'dcerpc-epm.c',
  'dcerpc-server.c',
  'dcerpc-unicode.c',
  dcerpc_coders,
  include_directories: [
    include_dirs,
    libdcerpc_inc,
  ],
  c_args: [
    '-D_FILE_OFFSET_BITS=64',
    '-D_U_=__attribute__((unused))',
  ],
)

libdcerpc_dep = declare_dependency(
  link_with: libdcerpc_lib,
  include_directories: libdcerpc_inc,
  sources: dcerpc_headers,
)
