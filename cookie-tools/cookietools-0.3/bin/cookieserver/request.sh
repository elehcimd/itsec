#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# request.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# no options defined.


################################################################################

main() {

  logdir="$1"
  client="$2"
  static="$3"
  mydir="`echo $0 | rev | cut -f2- -d/ | rev`/"

  if [ "$static" != "static" ]
    then
      ${mydir}/build_tmp.sh "$logdir" "$client" >/dev/null 2>/dev/null
  fi

  request="`head -1`"
  hostrequest="`echo "$request" | cut -f3 -d/`"

  echo 'HTTP/1.1 200 OK'
  echo 'Server: CookieServer'
  echo 'Content-Type: text/html; charset=iso-8859-1'
  echo 'Connection: close'
  echo 'Cache-Control: no-cache'
  cat ${mydir}/tmp.cookies
  echo -ne "\n\n"
  echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"'
  echo '"http://www.w3.org/TR/html1/DTD/html1-strict.dtd">'
  echo '<html xmlns="http://www.w3.org/1999/xhtml">'
  echo '<head>'
  echo '<title>CookieServer</title>'
  echo '<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />'
  echo '</head><body>'
  
  echo "<h1>CookieServer</h1>"
  echo "<p><b>Logdir</b>: '$1'</p>"
  echo "<p><b>Client</b>: '$2'</p>"
  echo "<p><b>Faking host</b>: $hostrequest</p>"
  echo "<p><b>Cookie hosts</b> ("`cat ${mydir}/tmp.hosts |wc -l`"): </p><ul>"
  for i in `cat ${mydir}/tmp.hosts`
    do
      echo "<li><a href=\"http://$i\">$i</a> </li>"
    done
  echo "</ul>"
  echo "<p><b>Links</b> ("`cat ${mydir}/tmp.links |wc -l`"): </p><ul>"
  for i in `cat ${mydir}/tmp.links | sed 's/&/&amp;/g'`
    do
      echo "<li><a href=\"$i\">$i</a> </li>"
    done
  echo "</ul>"

  echo "<p><b>Set-Cookies</b> ("`cat ${mydir}/tmp.cookies |wc -l`"): </p><pre>"
  cat ${mydir}/tmp.cookies
  echo '</pre><p><b>EOF</b></p></body></html>'
}


################################################################################

main $@

# EOF

