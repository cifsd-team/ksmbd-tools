ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib mountd adduser addshare control

EXTRA_DIST = include \
             README.md \
             Documentation \
             ksmbd-tools.spec \
             ksmbd.service.in

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = smb.conf.example

systemdsystemunit_DATA = ksmbd.service
$(systemdsystemunit_DATA): %: %.in
	@$(SED) -e 's,[@]sbindir[@],$(sbindir),g' \
	        -e 's,[@]runstatedir[@],$(runstatedir),g' \
	        $< >$@

CLEANFILES = $(systemdsystemunit_DATA)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$${dc_install_base}/$(systemdsystemunitdir)
