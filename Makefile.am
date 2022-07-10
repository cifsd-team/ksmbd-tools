## Makefile.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib mountd adduser addshare control

# other stuff
EXTRA_DIST =			\
	include			\
	Documentation		\
	ksmbd-tools.spec	\
	ksmbd.service.in

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = smb.conf.example

systemdsystemunit_DATA = ksmbd.service
$(systemdsystemunit_DATA): %: %.in ; @$(SED) 's,[@]sbindir[@],$(sbindir),g' $< >$@

CLEANFILES = $(systemdsystemunit_DATA)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$${dc_install_base}/$(systemdsystemunitdir)
