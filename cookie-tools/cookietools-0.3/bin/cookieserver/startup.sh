#!/bin/bash
PATH=${PATH}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
################################################################################
#
# startup.sh by xenion -- Thu Nov 22 20:46:06 CET 2007
#

# options
listenport="8181"


################################################################################

main() {


  if [ $# -lt 2 ]
    then
      echo "Copyright (c) 2007 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>"
      echo
      echo "usage: $0 log_directory client_ip ['static']"
      echo
      exit
  fi


  check_bins "socat sed grep egrep cut cat head sort tail uniq"

  logdir="$1"
  client="$2"
  static="$3"


  echo "checking log directory..."
  if [ ! -d "$logdir" ]; then fatal "logdir '$logdir' doesn't exist"; fi

  l="`ls -1 ${logdir}/${client}-*.* 2>/dev/null | wc -l`"
  if [ $l -eq 0 ]
    then
    if [ "$static" == "static" ]; then fatal "no matching log files: '$logdir/$client-*.*'"; fi
    echo "warning: (yet) no matching log files: '$logdir/$client-*.*'"
  fi

  mydir="`echo $0 | rev | cut -f2- -d/ | rev`/"

  trap cleanup EXIT
  
  echo "Client: '$client' Logdir: '$logdir'"
  echo "Cookie Server: 127.0.0.1:$listenport"

  if [ "$static" == "static" ]
    then
      echo "tmp files will be generated only once (faster but static)"
      $mydir/build_tmp.sh "$logdir" "$client"
    else
      echo "tmp files will be generated at each request (slower but dynamic)"
  fi    
  
  echo "Listening..."
  
  # add -v to see i/o
  socat "TCP4-LISTEN:${listenport},reuseaddr,fork" \
        "EXEC:${mydir}/request.sh $logdir $client $static,stderr"
  
  
}


cleanup()
{
  echo "Exiting..."
  rm -f ${mydir}/tmp.cookies ${mydir}/tmp.links ${mydir}/tmp.hosts ${mydir}/tmp.cookies2
}


check_bins()
{
  local list="$1"
  local i

  echo -n "checking for: "


  for i in $list
  do
   echo -n "$i "

   which "$i" 2>&1>/dev/null
   RETURN="$?"

   if [ "$RETURN" -ne 0 ]
     then
       echo FAILED
       fatal "'$i' executable not found in PATH"
   fi
  done

  echo
}


fatal()
{
  echo
  echo "*** FATAL ERROR: $1; exit forced."
  echo
  exit
}


################################################################################

main $@

# EOF

