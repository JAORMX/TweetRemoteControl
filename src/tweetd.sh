#!/bin/bash

case "$1" in
'start')
printf "Starting tweetd\n"
$(pwd)/tweetd
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
