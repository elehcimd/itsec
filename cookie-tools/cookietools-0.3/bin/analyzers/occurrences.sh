#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################

# this script doesn't work well if the same client has cookies from different
# sites with the same cookie name.

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

    cookienames="`cat ${client}-*.session | grep " Set-Cookie: " | \
     cut -f3 -d' ' | cut -f1 -d= | sort | uniq`"
    
    for i in $cookienames
      do 
        echo ----- $i -----
        cat ${client}-*.session | grep " Set-Cookie: ${i}=" | \
         cut -f3 -d' ' | sort | uniq -c
        echo
      done
    done  
}


################################################################################

main $@

# EOF

