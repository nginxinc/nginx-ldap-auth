#!/bin/sh

CMD=./ngx-ldap-auth-daemon.py
PIDFILE=./ngx-ldap-auth-daemon.pid
LOGFILE=./ngx-ldap-auth-daemon.log

case $1 in
    "start")
        start-stop-daemon -S -x $CMD -b -m -p $PIDFILE -1 $LOGFILE
    ;;
    "stop")
        start-stop-daemon -K -p $PIDFILE
    ;;
    *)
        echo "Usage: $0 <start|stop>"
    ;;
esac
