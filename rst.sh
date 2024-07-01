#!/bin/sh
systemctl stop block
echo -n >/var/log/block.log
#ipset flush autoblacklist
iptables -t raw -Z
echo -n >/var/log/btmp
systemctl start block
echo "Cleared logs, restarted 'block'."
echo "$(ipset list autoblacklist -output save|grep '^add'|wc -l) IP addresses in set."
