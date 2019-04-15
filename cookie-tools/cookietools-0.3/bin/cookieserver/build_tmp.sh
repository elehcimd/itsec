#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# build_tmp.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# no options defined.


################################################################################

main() {

  logdir="$1"
  client="$2"
  mydir="`echo $0 | rev | cut -f2- -d/ | rev`/"
  
  
  echo "Building tmp files... (logdir: '$logdir' client: '$client')"
  
  for i in `cat ${logdir}/${client}-*.session | grep " Set-Cookie: " | cut -f3 -d' ' | cut -f1 -d= | sort | uniq`
    do
      cat ${logdir}/${client}-*.session | \
       grep " Set-Cookie: ${i}=" | \
       sort -n | \
       tail -1 | \
       cut -f2- -d' '
    done >${mydir}/tmp.cookies

  ${mydir}/subset.sh
  
  cat ${logdir}/${client}-*.session | grep " Set-Cookie: " | \
    tr ' ;' '\n' | grep domain | cut -f2 -d= | \
    sed 's/^\.//' | sort | uniq >${mydir}/tmp.hosts
 
  cat ${logdir}/${client}-*.session | grep " Link: " | \
    sort | uniq | cut -f3 -d' ' | \
    egrep -vi '\.((ico|gif|jpg)|js|css|png)$' >${mydir}/tmp.links
}


################################################################################

main $@

# EOF

