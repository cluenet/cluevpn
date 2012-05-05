#!/bin/sh
### BEGIN INIT INFO
# Provides:             cluevpn
# Required-Start:       $network $syslog
# Required-Stop:        $network $syslog
# Default-Start:        2 3 4 5
# Default-Stop:
# Short-Description:    ClueVPN daemon
### END INIT INFO

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
NAME="cluevpn"
DESC="ClueVPN Client"
DAEMON="/usr/sbin/$NAME"
DAEMON_OPTS="-c /etc/cluevpn"
PIDFILE="/var/run/$NAME.pid"

test -x $DAEMON || exit 5

. /lib/lsb/init-functions

set -e

cluevpn_start() {
    if [ -f $PIDFILE ]; then
        return 2
    fi
    start-stop-daemon --start --quiet --pidfile $PIDFILE --oknodo \
        --exec $DAEMON --make-pidfile \
        -- $DAEMON_OPTS > /dev/null 2>&1 || return 1
    return 0
}

cluevpn_stop() {
    start-stop-daemon --stop --quiet --pidfile $PIDFILE \
        --oknodo || return 1
    rm -f $PIDFILE
    return 0
}

cluevpn_reload() {
    start-stop-daemon --stop --quiet --pidfile $PIDFILE \
        --signal HUP || return 1
    return 0
}

case "$1" in
    start)
        log_begin_msg "Starting $DESC: $NAME"
        cluevpn_start
        log_end_msg $?
    ;;
    stop)
        log_begin_msg "Stopping $DESC: $NAME"
        cluevpn_stop
        log_end_msg $?
    ;;
    reload)
        log-begin_msg "Reloading $DESC: $NAME"
        cluevpn_reload
        log_end_msg $?
        ;;
    restart|force-reload)
        log_begin_msg "Restarting $DESC: $NAME"
        cluevpn_stop && sleep 1 && cluevpn_start
        log_end_msg $?
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|force-reload}" >&2
        exit 1
        ;;
esac

exit 0
