#! /bin/sh

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
DAEMON="/usr/local/sbin/cluevpn"
NAME="cluevpn"
DESC="ClueVPN Client"
PIDFILE="/var/run/$NAME.pid"
DAEMON_OPTS="-c /etc/cluevpn"

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
    #start-stop-daemon --stop --quiet --pidfile $PIDFILE \
#	--oknodo || return 1
	killall cluevpn
    rm -f $PIDFILE
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
    #reload)
	#
	#	If the daemon can reload its config files on the fly
	#	for example by sending it SIGHUP, do it here.
	#
	#	If the daemon responds to changes in its config file
	#	directly anyway, make this a do-nothing entry.
	#
	# echo "Reloading $DESC configuration files."
	# start-stop-daemon --stop --signal 1 --quiet --pidfile \
	#	/var/run/$NAME.pid --exec $DAEMON
        #;;
    restart|force-reload)
	#
	#	If the "reload" option is implemented, move the "force-reload"
	#	option to the "reload" entry above. If not, "force-reload" is
	#	just the same as "restart".
	#
        log_begin_msg "Restarting $DESC: $NAME"
        cluevpn_stop && sleep 1 && cluevpn_start
        log_end_msg $?
	;;
    *)
	# echo "Usage: $0 {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $0 {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
