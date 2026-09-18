#!/bin/sh
# Entrypoint of the devnet's Postfix containers. Context: devnet image.
#
#   postfix.sh relay <hostname>
#       Outbound MTA of a modern domain: takes mail from the local sendmail
#       command (idmx queue run) and delivers it by MX lookup.
#   postfix.sh mx <hostname> <mailbox>...
#       SMTP-only MX: accepts the given mailboxes into
#       /var/mail/vhosts/<domain>/<user>/ (Maildir).
set -eu

role=$1 hostname=$2
shift 2

[ -f /etc/postfix/master.cf ] || cp /usr/share/postfix/master.cf.dist /etc/postfix/master.cf
cat >/etc/postfix/main.cf <<CONF
compatibility_level = 3.6
myhostname = $hostname
mydestination =
maillog_file = /dev/stdout
# *.test only lives in the devnet's CoreDNS.
smtp_host_lookup = dns
smtp_tls_security_level = may
CONF

case $role in
relay)
    postconf -e "inet_interfaces = loopback-only"
    ;;
mx)
    domains="" maps=""
    for mailbox in "$@"; do
        user=${mailbox%@*} domain=${mailbox#*@}
        domains="$domains $domain"
        maps="$maps { $mailbox = $domain/$user/ }"
    done
    groupadd -g 5000 vmail
    useradd -u 5000 -g vmail -d /var/mail/vhosts -M vmail
    install -d -o vmail -g vmail /var/mail/vhosts
    postconf -e "inet_interfaces = all" \
        "virtual_mailbox_domains =$domains" \
        "virtual_mailbox_base = /var/mail/vhosts" \
        "virtual_mailbox_maps = inline:{$maps }" \
        "virtual_uid_maps = static:5000" \
        "virtual_gid_maps = static:5000"
    ;;
*)
    echo "unknown role: $role" >&2
    exit 64
    ;;
esac

# No chroot: the services must see the container's /etc/resolv.conf.
postconf -F '*/*/chroot = n'
exec postfix start-fg
