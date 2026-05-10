ACLOCAL_AMFLAGS = -I m4

SUBDIRS = addshare adduser control mountd tools

EXTRA_DIST = include \
             README.md \
             ksmbd-tools.spec \
             ksmbd.conf.5.in \
             ksmbdpwd.db.5.in \
             ksmbd.service.in \
	     meson.build \
	     meson_options.txt

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = ksmbd.conf.example

man_MANS = ksmbd.conf.5 ksmbdpwd.db.5
systemdsystemunit_DATA = ksmbd.service
$(man_MANS) $(systemdsystemunit_DATA): %: %.in; @$(in_script) $< >$@

CLEANFILES = $(man_MANS) $(systemdsystemunit_DATA)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$${dc_install_base}/$(systemdsystemunitdir)

# Create runtime and configuration directories, and install default config if missing.
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(runstatedir)
	chmod 755 $(DESTDIR)$(runstatedir)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/ksmbd
	@if test ! -f $(DESTDIR)$(sysconfdir)/ksmbd/ksmbd.conf; then \
		echo "Installing default ksmbd.conf to $(sysconfdir)/ksmbd/"; \
		$(INSTALL_DATA) $(srcdir)/ksmbd.conf.example $(DESTDIR)$(sysconfdir)/ksmbd/ksmbd.conf; \
	fi

# Remove installed configuration file during uninstall to pass distcheck.
uninstall-hook:
	@if test -f $(DESTDIR)$(sysconfdir)/ksmbd/ksmbd.conf; then \
		rm -f $(DESTDIR)$(sysconfdir)/ksmbd/ksmbd.conf; \
	fi
