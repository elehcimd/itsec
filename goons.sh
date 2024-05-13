#!/bin/sh
#
# goons v0.5
#
# lame script that uses an hostname-list given by google in 
# order to perform dns/smtp/http scans:
#
#  ns - hosts with port 53 (probably) open (tcp|udp)
#  mx - hosts with port 25 (probably) open (tcp)
#  ht - hosts with port 80 (probably) open (tcp)
#
# ----------------------------------------------------------------------
# No part of this project may be used to break the law.
# xenion@antifork.org was here, have fun :)

# dig @
DNS="127.0.0.1"

# N is padded to PAD entries
PAD=10

# enable/disable bind.version grabbing (if TYPE == ns)
GRAB_VERSION="y" # y/n

# ----------------------------------------------------------------------


if [ $# -ne 4 ]
  then

cat <<EOF

goons v0.5 running here.
USAGE: goons TYPE KEYWORD N LOGFILE

    TYPE

      ns  hosts with port 53 (probably) open (tcp|udp)
      mx  hosts with port 25 (probably) open (tcp)
      ht  hosts with port 80 (probably) open (tcp)

    KEYWORD

      everything that returns tons of google results

    N

      expected value for 'cat logfile | wc -l'

    LOGFILE

      you know


EOF

   exit
fi

TYPE="$1"
KEYWORD="$2"
NHOSTS="$3"
LOGFILE="$4"


# ----------------------------------------------------------------------
# misc checks 
# ----------------------------------------------------------------------

found=0
for i in ht ns mx; do if [ $TYPE = $i ]; then found=1; fi; done

if [ $found -eq 0 ]
  then
   echo -e "$0: TYPE != (ht|ns|mx)\n"
   exit
fi

if [ -e $LOGFILE ]
  then
   echo -e "$0: LOGFILE already exists\n"
   exit
fi

echo "# TYPE.....: $TYPE"
echo "# KEYWORD..: \"$KEYWORD\""
echo "# NHOSTS...: $NHOSTS"
echo "# LOGFILE..: $LOGFILE"
echo

date > $LOGFILE
echo >> $LOGFILE


# ----------------------------------------------------------------------
# setup tmp pathname
# ----------------------------------------------------------------------

x=$((ps aux|md5sum && ps aux|md5sum) | tr -cd 0-9 | cut -b 1-10)
TMP=".gog.$x"

rm -f ${TMP}*


# ----------------------------------------------------------------------
# getting hostname-list from google
# ----------------------------------------------------------------------

i=0
while [ $i -lt $NHOSTS ]; do i=$[i+PAD]; done

echo "+ asking to google $i hostnames"

NHOSTS=$i
i=$PAD

while [ $i -le $NHOSTS ];
  do
   wget -q www.google.it/search?q=\"${KEYWORD}\"\&num=$PAD\&start=$i -U Explorer -O ${TMP}.0
   cat $TMP.0 | tr ' ' '\n' | grep -v google | grep -v search? | grep href= | grep http | grep \> | cut -f3 -d/ | sort | uniq >> $TMP  
   i=$[i+PAD];
 done

rm -f ${TMP}.0

if [ $TYPE = "ht" ]
  then
   echo "+ resolving hostname-list"
   dig +noall +answer +nostats +nocmd @$DNS A -f $TMP | tr -s "[\t]" | tr "[\t]" "[ ]" | grep -v " CNAME " | grep -v " cname " | cut -f5 -d' ' > ${TMP}.0
   sort ${TMP}.0 | uniq > $TMP
   rm ${TMP}.0
   mv $TMP $LOGFILE
   e=`wc -l $LOGFILE | cut -b 1-8`
   e=$[e-2]
   echo "+ scan finished. ($e entries)"
   echo
   rm -rf ${TMP}*
   exit
fi



# ----------------------------------------------------------------------
# expanding hostnames (ex: aa.bb.cc.dd -> cc.dd, bb.cc.dd, aa.bb.cc.dd)
# ----------------------------------------------------------------------

echo "+ expanding hostname-list"

e0=$(wc -l $TMP | cut -b 1-8)

for i in `cat $TMP`;
 do

  ndots=`echo $i | tr -d '\n' | tr '.' '\n' | wc -l`
  j=$[ndots+1]
  LIST=""

  while [ $j -gt 1 ];
   do
    j=$[j-1]
    LIST=${LIST}${j},
    echo $i | cut -f${LIST}$[ndots+1] -d. >> ${TMP}.0
   done

 done

sort ${TMP}.0 | uniq > $TMP

e1=$(wc -l $TMP | cut -b 1-8)
e0=$[e0];
e1=$[e1];

echo "  $e0 > $e1"

rm -f ${TMP}.0


# ----------------------------------------------------------------------
# getting mx/ns host-list
# ----------------------------------------------------------------------

echo "+ getting $TYPE host-list"

dig +noall +answer +nostats +nocmd @$DNS $TYPE -f $TMP > ${TMP}.0

if [ $TYPE = "mx" ]; then fields=6 ; fi
if [ $TYPE = "ns" ]; then fields=5 ; fi

cat ${TMP}.0 | tr -s "[\t]" | tr "[\t]" "[ ]" | cut -f$fields -d' ' > $TMP
sort $TMP | uniq > ${TMP}.0 2> /dev/null
mv ${TMP}.0 $TMP


# ----------------------------------------------------------------------
# resolving mx/ns host-list
# ----------------------------------------------------------------------

echo "+ resolving $TYPE host-list"
dig +noall +answer +nostats +nocmd @$DNS A -f $TMP | tr -s "[\t]" | tr "[\t]" "[ ]" | grep -v " CNAME " | grep -v " cname " | cut -f5 -d' ' > ${TMP}.0
sort ${TMP}.0 | uniq > ${TMP}
rm ${TMP}.0


if [ $TYPE = "mx" ]
  then
  GRAB_VERSION="n"
fi

if [ $GRAB_VERSION = "n" ]
  then
   mv $TMP $LOGFILE
   TYPE="just_exit"
fi


# ----------------------------------------------------------------------
# grabs bind.version
# ----------------------------------------------------------------------

if [ $TYPE = "ns" ]
  then
   echo "+ grabbing bind.version"
   for i in `cat ${TMP}`; do
    ip=`echo $i | cut -f2 -d:`
    BIND_VERSION="`dig +nostats +nocomments +nocmd +noall +answer @$ip version.bind chaos txt 2> /dev/null`"
    echo "$i: $BIND_VERSION" >> $LOGFILE
   done
fi

e=`wc -l $LOGFILE | cut -b 1-8`
e=$[e-2]

echo "+ scan finished. ($e entries)"
echo

rm -rf ${TMP}*


# ----------------------------------------------------------------------
# EOF
