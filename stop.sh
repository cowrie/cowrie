#!/bin/sh

PIDFILE=cowrie.pid

cd $(dirname $0)

PID=$(cat $PIDFILE 2>/dev/null)

if [ -n "$PID" ]; then
  echo "Stopping cowrie...\n"
  kill -TERM $PID
fi
