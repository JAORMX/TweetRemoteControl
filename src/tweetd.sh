#!/bin/bash
# SRC_DIR is the directory where the binary is.
#
SRC_DIR=

case "$1" in
'start')
printf "Starting tweetd\n"
if [ -z "${SRC_DIR}" ]; then 
$(pwd)/tweetd;
else
${SRC_DIR}/tweetd;
fi
;;

'stop')
printf "Stoping tweetd\n"
pkill tweetd
;;

'restart')
printf "Restarting tweetd\n"
pkill -HUP tweetd
;;

esac
