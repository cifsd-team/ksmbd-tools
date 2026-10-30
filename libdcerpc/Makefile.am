# libdcerpc, a copy of libsmb2's libdcerpc/ (see README.ksmbd-tools):
# the coders and the server runtime without the libsmb2 transport,
# linked statically into ksmbd.tools. Nothing is installed.

# Interfaces whose coders and public header dcerpc/<iface>.h are
# generated from <iface>/<iface>.idl at build time, by idlcomp.py.
IDLS = srvsvc/srvsvc.idl \
       wkssvc/wkssvc.idl \
       winreg/winreg.idl \
       lsa/lsa.idl \
       samr/samr.idl \
       dssetup/dssetup.idl \
       netlogon/netlogon.idl \
       epm/epm.idl
CODERS = srvsvc_coder.c \
         wkssvc_coder.c \
         winreg_coder.c \
         lsa_coder.c \
         samr_coder.c \
         dssetup_coder.c \
         netlogon_coder.c \
         epm_coder.c
GEN_HDRS = dcerpc/srvsvc.h \
              dcerpc/wkssvc.h \
              dcerpc/winreg.h \
              dcerpc/lsa.h \
              dcerpc/samr.h \
              dcerpc/dssetup.h \
              dcerpc/netlogon.h \
              dcerpc/epm.h

AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/include -D_FILE_OFFSET_BITS=64 \
              "-D_U_=__attribute__((unused))"

noinst_LIBRARIES = libdcerpc.a
libdcerpc_a_SOURCES = dcerpc.c dcerpc-dtyp.c dcerpc-epm.c dcerpc-server.c \
                      dcerpc-unicode.c dcerpc-private.h \
                      include/dcerpc/dcerpc.h include/dcerpc/dcerpc-dtyp.h \
                      include/dcerpc/schannel.h include/dcerpc/server.h
nodist_libdcerpc_a_SOURCES = $(CODERS)

# mountd includes the generated headers, so they are built before
# anything else is compiled.
BUILT_SOURCES = $(CODERS) $(GEN_HDRS)

IDLCOMP = $(PYTHON3) $(srcdir)/idlcomp.py

# Both files come from the one idlcomp run. The .c is written under a
# temporary name so that a failed run is retried by the next make.
$(CODERS): %_coder.c: $(srcdir)/idlcomp.py
	$(AM_V_GEN)$(MKDIR_P) dcerpc && \
	$(IDLCOMP) $(srcdir)/$*/$*.idl --libdcerpc -o $@.tmp \
		--header dcerpc/$*.h >/dev/null && \
	mv $@.tmp $@
srvsvc_coder.c: srvsvc/srvsvc.idl
wkssvc_coder.c: wkssvc/wkssvc.idl
winreg_coder.c: winreg/winreg.idl
lsa_coder.c: lsa/lsa.idl
samr_coder.c: samr/samr.idl
dssetup_coder.c: dssetup/dssetup.idl
netlogon_coder.c: netlogon/netlogon.idl
epm_coder.c: epm/epm.idl

# Regenerate if only the header is missing.
$(GEN_HDRS): dcerpc/%.h: %_coder.c
	@test -f $@ || { rm -f $<; $(MAKE) $(AM_MAKEFLAGS) $<; }

CLEANFILES = $(CODERS) $(CODERS:.c=.c.tmp) $(GEN_HDRS)

clean-local:
	-rmdir dcerpc

EXTRA_DIST = $(IDLS) idlcomp.py COPYING README README.ksmbd-tools \
             meson.build include/dcerpc/meson.build
