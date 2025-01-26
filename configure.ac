AC_INIT([cjose],[1.0.0],[hans.zandbelt@openidc.com])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign subdir-objects])

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AM_PROG_AR
LT_INIT([dlopen])

PKG_CHECK_MODULES([OPENSSL], [openssl >= 3.0.0])

PKG_CHECK_MODULES([JANSSON], [jansson])

AC_MSG_CHECKING([for RSA PKCS v1.5])
AC_ARG_WITH(
    [rsapkcs1_5],
    [AS_HELP_STRING([--with-rsapkcs1_5], [Enable risky RSA PKCS v1.5])],
    [rsapkcs1_5=${withval}],
    [rsapkcs1_5=no])
AC_MSG_RESULT([$rsapkcs1_5])
if test "x$rsapkcs1_5" == xyes ; then
    AC_DEFINE(HAVE_RSA_PKCS1_PADDING, 1)
fi

DX_FEATURE_pdf([OFF])
DX_FEATURE_ps([OFF])
DX_INIT_DOXYGEN([CJOSE], [Doxyfile], [doc])

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check="yes"], [have_check="no"]; [AC_MSG_WARN([Check not found; cannot run unit tests!])])
AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")

AM_EXTRA_RECURSIVE_TARGETS([package])
AC_CONFIG_FILES([Makefile
                 include/Makefile include/cjose/version.h
                 src/Makefile
                 test/Makefile
                 doc/Makefile doc/Doxyfile
                 cjose.pc])

AC_OUTPUT

echo "
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix.........: $prefix
  Using OpenSSL..: $OPENSSL_LIBS
  Using Jansson..: $JANSSON_LIBS
  RSA PKCS v1.5  : $rsapkcs1_5
  Unit tests.....: $have_check
"
