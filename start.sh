#!/bin/sh
AUTHBIND_ENABLED=no
COWRIEDIR=$(dirname $0)
PIDFILE="var/run/cowrie.pid"
export PYTHONPATH=${PYTHONPATH}:${COWRIEDIR}

set -e
cd ${COWRIEDIR}

if [ "$1" != "" ]
then
    VENV="$1"

    if [ ! -d "$VENV" ]
    then
        echo "The specified virtualenv \"$VENV\" was not found!"
        exit 1
    fi

    if [ ! -f "$VENV/bin/activate" ]
    then
        echo "The specified virtualenv \"$VENV\" was not found!"
        exit 2
    fi

    echo "Activating virtualenv \"$VENV\""
    . $VENV/bin/activate
fi

echo "Starting cowrie with extra arguments [$XARGS] ..."
if [ $AUTHBIND_ENABLED = "no" ]
then
    twistd $XARGS -l log/cowrie.log --umask 0077 --pidfile ${PIDFILE} cowrie
else
    authbind --deep twistd $XARGS -l log/cowrie.log --umask 0077 --pidfile cowrie.pid cowrie
fi
