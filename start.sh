#!/bin/sh

echo -n "Starting kippo..."

if [ "$1" == "-f" ]
then
    FOREGROUND=" -n"
else
    echo -n " (background)"
fi
echo

twistd -y kippo.tac -l log/kippo.log$FOREGROUND
