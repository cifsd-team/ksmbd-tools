# One idlcomp run per interface writes both <iface>_coder.c and the
# public header <iface>.h, here in the build tree.

dcerpc_coders = []
dcerpc_headers = []
foreach iface : dcerpc_ifaces
  gen = custom_target(
    iface + '_coder',
    input: dcerpc_idls[iface],
    output: [
      iface + '_coder.c',
      iface + '.h',
    ],
    command: [
      python3,
      idlcomp,
      '@INPUT@',
      '--libdcerpc',
      '-o', '@OUTPUT0@',
      '--header', '@OUTPUT1@',
    ],
    depend_files: idlcomp,
  )
  dcerpc_coders += gen[0]
  dcerpc_headers += gen[1]
endforeach
