AM_CFLAGS = -I$(top_srcdir)/include $(GLIB_CFLAGS)
check_PROGRAMS = quota-test rpc-test
TESTS = $(check_PROGRAMS)
quota_test_SOURCES = quota.c ../mountd/quota.c
quota_test_LDADD = $(GLIB_LIBS)
quota_test_LDFLAGS = -Wl,--wrap=open,--wrap=open64,--wrap=close,--wrap=fstat,--wrap=fstat64,--wrap=__fxstat,--wrap=__fxstat64,--wrap=fstatfs,--wrap=fstatfs64,--wrap=syscall,--wrap=ioctl
rpc_test_SOURCES = rpc.c
rpc_test_LDADD = $(top_builddir)/mountd/libmountd.a $(GLIB_LIBS)
EXTRA_DIST = meson.build
