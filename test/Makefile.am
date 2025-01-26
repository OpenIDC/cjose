if HAVE_CHECK

AM_CPPFLAGS =-std=gnu99 --pedantic -Wall -g -O2 -I$(top_srcdir)/include

AM_CPPFLAGS += @CHECK_CFLAGS@
TESTS = check_cjose

check_PROGRAMS = $(TESTS)
check_cjose_CFLAGS = @CHECK_CFLAGS@ \
                     -I$(top_srcdir)/include \
                     -I$(top_srcdir)/src \
                     @OPENSSL_CFLAGS@ @JANSSON_CFLAGS@
check_cjose_LDADD = $(top_builddir)/src/libcjose.la @CHECK_LIBS@ @OPENSSL_LIBS@ @JANSSON_LIBS@
check_cjose_SOURCES = check_cjose.c \
                      check_version.c \
                      check_util.c \
                      check_base64.c \
                      check_concatkdf.c \
                      check_jwk.c \
                      check_jwe.c \
                      check_jws.c \
                      check_header.c \
                      check_cjose.h 

endif

DOCKER_TAG=cjose/test

docker-build:
	docker build --progress plain -f test/Dockerfile . -t $(DOCKER_TAG)

DOCKER_RUN_ARGS := -e CK_FORK=no -e LD_LIBRARY_PATH=/usr/local/lib:/root/cjose/src/.libs

docker-check: docker-build
	docker run -it $(DOCKER_RUN_ARGS) --rm $(DOCKER_TAG):latest bash -c "make check || cat test/test-suite.log"

VALGRIND_FLAGS := -s --leak-check=full --show-leak-kinds=definite --read-inline-info=yes --keep-debuginfo=yes 

docker-valgrind: docker-build
	docker run -it $(DOCKER_RUN_ARGS) --rm $(DOCKER_TAG):latest /usr/bin/valgrind ${VALGRIND_FLAGS} test/.libs/check_cjose

docker-gdb: docker-build
	docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm $(DOCKER_RUN_ARGS) $(DOCKER_TAG):latest /usr/bin/gdb test/.libs/check_cjose
