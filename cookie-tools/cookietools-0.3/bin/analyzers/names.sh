#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# names.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
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

    cookiehosts="`cat ${client}-*.session | \
      grep " Set-Cookie: " | tr ' ;' '\n' | \
      grep domain | cut -f2 -d= | sed 's/^\.//' | \
      rev | cut -f-2 -d. | rev | sort | uniq`"

    for host in $cookiehosts
      do
        echo "----- Cookies under $host -----" 
        cat ${client}-*.session | grep " Set-Cookie: " | egrep " domain=*.${host};" | \
          cut -f3 -d' ' | cut -f1 -d= | sort | uniq
        echo
      done
  done
}


################################################################################

main $@

# EOF

