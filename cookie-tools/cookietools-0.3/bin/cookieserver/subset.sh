#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# subset.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# this script is disabled by default.
exit

# enable only cookie names in the list
list="GX" # gmail example :)

################################################################################

main() {

  mydir="`echo $0 | rev | cut -f2- -d/ | rev`/"

  s="(^\\\$)" # empty line, never happens.
  for i in $list
    do
      s="${s}|(\\ ${i}=)"
    done
  
  cat ${mydir}/tmp.cookies | egrep "$s" >${mydir}/tmp.cookies2
  mv ${mydir}/tmp.cookies2 ${mydir}/tmp.cookies
}


################################################################################

main $@

# EOF

