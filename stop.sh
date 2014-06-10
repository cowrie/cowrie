#!/bin/sh

PIDFILE=kippo.pid

cd $(dirname $0)

PID=$(cat $PIDFILE 2>/dev/null)

if [ -n "$PID" ]; then
  echo -e "[\e[01;32mi\e[00m] Stopping kippo...\n"
  kill -TERM $PID
fi