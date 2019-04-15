dnl =========================================================
dnl  libimbw autoconfiguration information file, process this
dnl  file with autoconf to produce a configure script.
dnl =========================================================

AC_INIT([libimbw],[x],[Dallachiesa Michele <xenion@antifork.org>])
AC_CONFIG_SRCDIR([src/imbw_main.c])
AC_CONFIG_HEADER([include/config.h])

SB=`./shtool echo -e %B`
EB=`./shtool echo -e %b`

LIBNAME=imbw
VERSION=`cat VERSION`

PLUGINS=""

for i in src/imbw_plugin_*.c; do PLUGINS="$PLUGINS $(echo $i | cut -f3 -d_ | cut -f1 -d.)"; done

echo
echo "  ${SB}Beginning autoconfiguration process for lib${LIBNAME}-${VERSION}...${EB}"
echo

AC_SUBST(DEFS)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(AR)
AC_SUBST(PLUGINS)
AC_SUBST(LIBNAME)
AC_SUBST(SB)
AC_SUBST(EB)
AC_SUBST(VERSION)
AC_SUBST(INCLS)
AC_SUBST(LIBIMBW_CONFIG_DEFINES)
AC_SUBST(LIBIMBW_CONFIG_CFLAGS)
AC_SUBST(LIBIMBW_CONFIG_LIBS)

SOURCES=`ls ./src/imbw_*.c | cut -b 7- | awk ' { printf "%s ", $1 } '`
AC_SUBST(SOURCES)


dnl ===================
dnl Check compiler type
dnl ===================

AC_PROG_CC

dnl ===================
dnl Checks for programs
dnl ===================

AC_CHECK_PROGS(SHTOOL, shtool, ./shtool)
AC_CHECK_PROGS(AR, ar, @true)
AC_PROG_MAKE_SET

dnl ===========================
dnl Determines host system type
dnl ===========================

AC_CANONICAL_HOST

case "$host_os" in
linux*) ;;
*)          rm -Rf *.cache *.log
            AC_MSG_ERROR($host_os is not supported);;
esac

dnl =======================================
dnl Use these compiler flags if we have gcc
dnl =======================================

CFLAGS=""

if test $ac_cv_prog_gcc = yes; then
dnl if test -z $CFLAGS; then
    CCOPTS="-O2 -funroll-loops -fomit-frame-pointer -Wall"
    CFLAGS="$CCOPTS $CFLAGS"
dnl fi
fi

dnl ====================
dnl Checks for libraries
dnl ====================

AC_CHECK_LIB([pcap], [pcap_open_live], have_pcap=yes, have_pcap=no)
if test $have_pcap = no ; then
        rm -Rf *.cache *.log
        AC_MSG_ERROR([this os doesn't support pcap library])
fi

AC_CHECK_LIB([pthread], [pthread_create], have_pthread=yes, have_pthread=no)
if test $have_pthread = no ; then
        rm -Rf *.cache *.log
        AC_MSG_ERROR([this os doesn't support pthread library])
fi

AC_CHECK_LIB([crypto], [BF_set_key], have_crypto=yes, have_crypto=no)
if test $have_crypto = no ; then
        rm -Rf *.cache *.log
        AC_MSG_ERROR([this os doesn't support crypto library])
fi

AC_CHECK_LIB([crypto], [BF_cfb64_encrypt], have_crypto=yes, have_crypto=no)
if test $have_crypto = no ; then
        rm -Rf *.cache *.log
        AC_MSG_ERROR([this os doesn't support crypto library])
fi

dnl =======================
dnl Checks for header files
dnl =======================

AC_HEADER_STDC

AC_PCAP_HEADER_CHECK(INCLS)
AC_OPENSSL_HEADER_CHECK(INCLS)
AC_CHECK_HEADERS([errno.h pcap-int.h arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h termios.h unistd.h netinet/ip.h netinet/tcp.h netinet/udp.h blowfish.h])

AC_CHECK_HEADERS(queue.h)

dnl =============================================================
dnl Checks for typedefs, structures, and compiler characteristics
dnl =============================================================

AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl ============================
dnl Checks for library functions
dnl ============================

AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname gettimeofday inet_ntoa memset select socket strcasecmp strdup strerror vprintf getdtablesize])

dnl ==================
dnl checks for options
dnl ==================

AH_TEMPLATE(RANDOM_FILE, [user-specified random device])
AH_TEMPLATE(DEBUG, [debug support])


ac_cv_imbw_debug=no
AC_MSG_CHECKING([if --enable-debug option is specified])
AC_ARG_ENABLE(debug, [  --enable-debug          create a file for debugging messages.],
[ case "$enableval" in
   yes)
      AC_DEFINE(DEBUG, 1)
      AC_MSG_RESULT(yes)
      ac_cv_imbw_debug=yes
      ;;
   no)  AC_MSG_RESULT(no.)
      ;;
esac ],
   AC_MSG_RESULT(no. Disabled by default.)
)


dnl Check for user-specified random device
AC_ARG_WITH(random,
    [  --with-random=FILE      read randomness from FILE (default=/dev/urandom)],
    [ RANDOM_FILE="$withval" ],
    [
        dnl Check for random device
        AC_CHECK_FILE("/dev/urandom",
            [
                RANDOM_FILE="/dev/urandom";
            ]
        )
    ]
)
if test -n "$RANDOM_FILE" ; then
        AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE")
fi


dnl ====================
dnl set config variables
dnl ====================

LIBIMBW_CONFIG_CFLAGS="$CFLAGS $INCLS"
LIBIMBW_CONFIG_LIBS="-lpcap -lpthread -lcrypto"
LIBIMBW_CONFIG_DEFINES=""
test $ac_cv_imbw_debug == yes && LIBIMBW_CONFIG_DEFINES="-DDEBUG"
test $ac_cv_imbw_debug == yes && CFLAGS="$CFLAGS -ggdb" && \
 LIBIMBW_CONFIG_CFLAGS="$LIBIMBW_CONFIG_CFLAGS -ggdb"

dnl ===================
dnl writes output files
dnl ===================

AC_CONFIG_FILES(Makefile src/Makefile libimbw-config libimbw-checkv)

echo
echo "  ${SB}Writing output files${EB}"
echo



AC_OUTPUT


chmod +x libimbw-checkv
chmod +x libimbw-config

echo
echo "  ${SB}The $LIBNAME package has been configured with the following options:${EB}"
echo
echo "    compiler       : $CC"
echo "    host_cpu       : $host_cpu"
echo "    host_vendor    : $host_vendor"
echo "    host_os        : $host_os"
echo "    cflags         : $CFLAGS"
echo "    cppflags       : $CPPFLAGS"
echo "    include        : $INCLS"
echo "    defs           : $DEFS"
echo "    debug enabled  : $ac_cv_imbw_debug"
echo "    random file    : $RANDOM_FILE"
echo "    CONFIG_CFLAGS  : $LIBIMBW_CONFIG_CFLAGS"
echo "    CONFIG_LIBS    : $LIBIMBW_CONFIG_LIBS"
echo "    CONFIG_DEFINES : $LIBIMBW_CONFIG_DEFINES"


echo
echo "  ${SB}built-in plugins:${EB}"
echo
for i in $PLUGINS; do echo "    $i"; done
echo
echo "  now type ${SB}make${EB}" 
echo
