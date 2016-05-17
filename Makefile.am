lib_LTLIBRARIES=libwitutil.la
libwitutil_la_CPPFLAGS= -DCLIENT_LIB_VERSION=0x$(shell cd ~/libwitutil;git log -1 --pretty=format:%h)
libwitutil_la_LDFLAGS=
libwitutil_la_SOURCES= \
	src/utils.c
libwitutil_la_DEPENDENCIES=

libwitutil_la_includedir= \
	$(includedir)
libwitutil_la_include_HEADERS= \
	src/witutil.h

libwitutil_la_LIBADD=$(libwitutil_la_DEPENDENCIES)
