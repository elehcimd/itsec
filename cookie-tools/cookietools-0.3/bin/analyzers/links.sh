#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# links.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# no options defined.


################################################################################

main() {

  if [ $# -lt 1 ]
    then
      echo usage: $0 log_directory
      exit
  fi
  
  logdir="$1"
  
  cd ${logdir}
  
  clients="`ls -1 *-* | cut -f1 -d- | sort | uniq`"
  
  for client in $clients
  do
    echo "======================== Client $client ========================"
    echo
    echo "----- Cookie hosts -----"
    cat ${client}-*.session | grep " Set-Cookie: " | tr ' ;' '\n' | \
      grep domain | cut -f2 -d= | sed 's/^\.//' | sort | uniq
    echo
    echo "----- Links -----"

    cat ${client}-*.session | grep " Link: " | \
      sort | uniq | cut -f3 -d' ' | \
      egrep -vi '\.((ico|gif|jpg)|js|css|png)$'
    echo
  done
}


################################################################################

main $@

# EOF

