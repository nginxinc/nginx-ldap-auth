#!/bin/sh

CMD=./nginx-ldap-auth-daemon.py
PIDFILE=./nginx-ldap-auth-daemon.pid

case $1 in
    "start")
        start-stop-daemon -S -x $CMD -b -m -p $PIDFILE
    ;;
    "stop")
        start-stop-daemon -K -p $PIDFILE
    ;;
    *)
        echo "Usage: $0 <start|stop>"
    ;;
esac
