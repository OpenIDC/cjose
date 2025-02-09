SUBDIRS = . test doc
EXTRA_DIST = CHANGELOG.md README.md LICENSE

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cjose.pc

AM_CFLAGS = -std=gnu99 --pedantic -Wall -Werror -g -O2 -I$(top_builddir)/include @OPENSSL_CFLAGS@ @JANSSON_CFLAGS@

lib_LTLIBRARIES = libcjose.la

libcjose_la_CPPFLAGS = -I$(top_srcdir)/include
libcjose_la_LDFLAGS = -no-undefined -lm
libcjose_la_LIBADD = @OPENSSL_LIBS@ @JANSSON_LIBS@

includesubdir = $(includedir)/cjose

includesub_HEADERS = \
	include/cjose/cjose.h \
	include/cjose/base64.h \
	include/cjose/jwk.h \
	include/cjose/jwe.h \
	include/cjose/jws.h \
	include/cjose/header.h \
	include/cjose/error.h \
	include/cjose/util.h \
	include/cjose/version.h

libcjose_la_SOURCES = \
	src/version.c \
	src/util.c \
	src/base64.c \
	src/concatkdf.c \
	src/jwk.c \
	src/jwe.c \
	src/jws.c \
	src/header.c \
	src/error.c \
	src/include/concatkdf_int.h \
	src/include/header_int.h \
	src/include/jwk_int.h \
	src/include/jwe_int.h \
	src/include/jws_int.h \
	src/include/util_int.h

doxygen:
	cd doc && $(MAKE) doxygen

clang-format:
	clang-format -i `find . -name *.[ch]`

docker-%:
	$(MAKE) -f test/Makefile.docker $@
