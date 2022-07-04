## Makefile.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib mountd adduser addshare control

# other stuff
EXTRA_DIST =			\
	include			\
	Documentation		\
	ksmbd-tools.spec	\
	ksmbd.service

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = smb.conf.example
