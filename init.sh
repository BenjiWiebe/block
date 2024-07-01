#!/usr/bin/bash
#either run this script every boot before starting 'block', or run it and save the iptables/ipset configuration and have it restore on boot
ipset create autoblacklist hash:ip family inet hashsize 4096 maxelem 5000
iptables -t raw -I PREROUTING -m set --match-set autoblacklist src -j DROP
