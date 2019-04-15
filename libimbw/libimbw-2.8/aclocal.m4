# aclocal.m4 generated automatically by aclocal 1.6.2 -*- Autoconf -*-

# Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

dnl
dnl Look for pcap headers directories
dnl
dnl usage:
dnl
dnl     AC_PCAP_HEADER_CHECK(incls)
dnl
dnl
AC_DEFUN(AC_PCAP_HEADER_CHECK,
[
        if test -z "$pcap_dir"
        then
          AC_MSG_CHECKING(for pcap header no regular directories)
          for pcap_dir in /usr/include/pcap /usr/local/include/pcap $prefix/include/pcap
          do
            if test -d $pcap_dir ; then
                p_incls="$p_incls -I$pcap_dir"
            fi
          done

          if test -z "$p_incls" ; then
            AC_MSG_RESULT(not found)
          else
            AC_MSG_RESULT(found $p_incls)
          fi
        else
          p_incls="$p_incls -I$pcap_dir/include"
        fi

        CPPFLAGS="$CPPFLAGS $p_incls"
        # Pcap header checks

        AC_CHECK_HEADER(net/bpf.h,,
            AC_MSG_ERROR([[header file net/bpf.h not found]]))
        AC_CHECK_HEADER(pcap.h,, AC_MSG_ERROR(Header file pcap.h not found.))

        $1=$p_incls
])



dnl
dnl Look for openssl headers directories
dnl
dnl usage:
dnl
dnl     AC_OPENSSL_HEADER_CHECK(incls)
dnl
dnl
AC_DEFUN(AC_OPENSSL_HEADER_CHECK,
[
        if test -z "$openssl_dir"
        then
          AC_MSG_CHECKING(for openssl header no regular directories)
          for openssl_dir in /usr/include/openssl /usr/local/include/openssl $prefix/include/openssl
          do
            if test -d $openssl_dir ; then
                o_incls="$o_incls -I$openssl_dir"
            fi
          done

          if test -z "$o_incls" ; then
            AC_MSG_RESULT(not found)
          else
            AC_MSG_RESULT(found $o_incls)
          fi
        else
          o_incls="$o_incls -I$openssl"
        fi

        $1=$o_incls
])

