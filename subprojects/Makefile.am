# libdcerpc (libsmb2/libdcerpc, configured by AC_CONFIG_SUBDIRS) is built
# here but not installed: mountd links it statically.
LIBDCERPC = libsmb2/libdcerpc

all-local:
	$(MAKE) -C $(LIBDCERPC) all

clean-local:
	$(MAKE) -C $(LIBDCERPC) clean

distclean-local:
	-$(MAKE) -C $(LIBDCERPC) distclean

# libdcerpc's own dist rules put its sources in the tarball. They run
# from libdcerpc's directory, two levels down, and automake wants the
# dist paths relative.
dist-hook:
	$(MKDIR_P) $(distdir)/$(LIBDCERPC)
	$(MAKE) -C $(LIBDCERPC) distdir \
		top_distdir="../../$(top_distdir)" \
		distdir="../../$(distdir)/$(LIBDCERPC)" \
		am__remove_distdir=: am__skip_length_check=: am__skip_mode_fix=:
