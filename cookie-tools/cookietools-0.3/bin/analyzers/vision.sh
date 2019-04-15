#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# vision.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# no options defined.



################################################################################

main() {

  if [ $# -lt 1 ]
    then
      echo "usage: $0 log_directory [client_ip]"
      exit
  fi
  
  logdir="$1"
  client_ip="$2"

  cd ${logdir}

  if [ "$client_ip" != "" ]
    then 
      clients="$client_ip"
    else  
      clients="`ls -1 *-* | cut -f1 -d- | sort | uniq`"
  fi    

  for client in $clients
  do
    echo "======================== Client $client ========================"
    echo

    links="`cat ${client}-*.session | grep " Link: " | sort | uniq | \
      cut -f3 -d' ' | egrep -vi '\.((ico|gif|jpg)|js|css|png)$'`"

    echo "----- Links -----"
    for link in $links
    do
      echo "link[$client] $link"
    done

    echo

    echo "----- Cookies -----"

    hosts="`cat ${client}-*.session | \
      grep " Set-Cookie: " | tr ' ;' '\n' | \
      grep domain | cut -f2 -d= | sed 's/^\.//' | \
      rev | cut -f-2 -d. | rev | sort | uniq | tr '\n' ' '`"

    echo "hosts[$client:$host] $hosts"
    echo

    for host in $hosts
      do
        cnames="`cat ${client}-*.session | grep " Set-Cookie: " | egrep " domain=*.${host};" | \
          cut -f3 -d' ' | cut -f1 -d= | sort | uniq | tr '\n' ' '`"
	  echo "names[$client:$host] $cnames"
	  for cname in $cnames
	    do
              cvalue="`cat ${client}-*.session | grep " Set-Cookie: ${cname}=" | \
	      egrep " domain=*.${host};" | sort -n | tail -1 | \
	      cut -f3 -d' ' | cut -f2 -d= | cut -f1 -d\;`"
	      echo "values[$client:$host] '$cname'='$cvalue'"
	    done  
        echo
      done
  done
}


################################################################################

main $@

# EOF

