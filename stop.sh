#!/bin/sh

PIDFILE=var/run/cowrie.pid

cd $(dirname $0)

PID=$(cat ${PIDFILE} 2>/dev/null)

if [ -n "$PID" ]; then
  echo "Stopping cowrie..."
  kill -TERM $PID
fi
