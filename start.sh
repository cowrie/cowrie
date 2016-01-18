#!/bin/sh
AUTHBIND_ENABLED=no

set -e

cd $(dirname $0)

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

echo "Starting cowrie in the background..."
if [ $AUTHBIND_ENABLED = "no" ]
then
    twistd -l log/cowrie.log --pidfile cowrie.pid cowrie
else
    authbind --deep twistd -l log/cowrie.log --pidfile cowrie.pid cowrie
fi
