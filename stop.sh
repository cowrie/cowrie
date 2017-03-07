#!/bin/sh

PIDFILE=var/run/cowrie.pid

echo
echo 'WARNING: stop.sh is deprecated and will be removed in the future.'
echo 'WARNING: you can start cowrie with "bin/cowrie stop"'
echo

cd $(dirname $0)

PID=$(cat ${PIDFILE} 2>/dev/null)

if [ -n "$PID" ]; then
  echo "Stopping cowrie..."
  kill -TERM $PID
fi
