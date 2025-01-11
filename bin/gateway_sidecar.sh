#!/bin/bash

set -ex

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

# Make a copy of the original resolv.conf
if [ ! -f /etc/resolv.conf.org ]; then
  cp /etc/resolv.conf /etc/resolv.conf.org
  echo "/etc/resolv.conf.org written"
fi

# Get K8S DNS servers (both IPv4 and IPv6)
if [ -z "$DNS_LOCAL_SERVER" ]; then
  if [ "$IPV4_ENABLED" == "true" ]; then
    DNS_LOCAL_SERVER=$(grep nameserver /etc/resolv.conf.org | awk '/nameserver [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $2}')
  fi
fi

if [ -z "$DNS_LOCAL_SERVER_V6" ]; then
  if [ "$IPV6_ENABLED" == "true" ]; then
    DNS_LOCAL_SERVER_V6=$(grep nameserver /etc/resolv.conf.org | awk '/nameserver ([0-9a-fA-F:]+:[0-9a-fA-F:]+)/ {print $2}')
  fi
fi

cat << EOF > /etc/dnsmasq.d/pod-gateway.conf
# DHCP server settings
interface=vxlan0
bind-interfaces

# Dynamic IPs assigned to PODs - we keep a range for static IPs
EOF

if [ "$IPV4_ENABLED" == "true" ]; then
  cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
    # IPv4 DHCP range
    dhcp-range=${VXLAN_IP_NETWORK}.${VXLAN_GATEWAY_FIRST_DYNAMIC_IP},${VXLAN_IP_NETWORK}.255,12h
EOF
fi

if [ "$IPV6_ENABLED" == "true" ]; then
  cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
    # IPv6 DHCP range
    # Using SLAAC + DHCPv6
    enable-ra
    dhcp-range=${VXLAN_IPV6_NETWORK}::${VXLAN_GATEWAY_FIRST_DYNAMIC_IP},${VXLAN_IPV6_NETWORK}::ffff,slaac,64,12h
EOF
fi

cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
# For debugging purposes, log each DNS query as it passes through
# dnsmasq.
log-queries

# Log lots of extra information about DHCP transactions.
log-dhcp

# Log to stdout
log-facility=-

# Clear DNS cache on reload
clear-on-reload

# /etc/resolv.conf cannot be monitored by dnsmasq since it is in a different file system
# and dnsmasq monitors directories only
# copy_resolv.sh is used to copy the file on changes
resolv-file=${RESOLV_CONF_COPY}
EOF

if [[ ${GATEWAY_ENABLE_DNSSEC} == true ]]; then
cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
  # Enable DNSSEC validation and caching
  conf-file=/usr/share/dnsmasq/trust-anchors.conf
  dnssec
EOF
fi

for local_cidr in $DNS_LOCAL_CIDRS; do
  if [[ $local_cidr =~ ":" ]]; then
    if [ "$IPV6_ENABLED" == "true" ] && [ -n "$DNS_LOCAL_SERVER_V6" ]; then
      cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
    # Send ${local_cidr} DNS queries to the K8S IPv6 DNS server
    server=/${local_cidr}/[${DNS_LOCAL_SERVER_V6}]
EOF
    fi
  else
    if [ "$IPV4_ENABLED" == "true" ] && [ -n "$DNS_LOCAL_SERVER" ]; then
      cat << EOF >> /etc/dnsmasq.d/pod-gateway.conf
    # Send ${local_cidr} DNS queries to the K8S IPv4 DNS server
    server=/${local_cidr}/${DNS_LOCAL_SERVER}
EOF
    fi
  fi
done

# Make a copy of /etc/resolv.conf
/bin/copy_resolv.sh

# Dnsmasq daemon
dnsmasq -k &
dnsmasq=$!

# inotifyd to keep in sync resolv.conf copy
# Monitor file content (c) and metadata (e) changes
inotifyd /bin/copy_resolv.sh /etc/resolv.conf:ce &
inotifyd=$!

_kill_procs() {
  echo "Signal received -> killing processes"

  kill -TERM $dnsmasq || /bin/true
  wait $dnsmasq
  rc=$?

  kill -TERM $inotifyd || /bin/true
  wait $inotifyd

  rc=$(( $rc || $? ))
  echo "Terminated with RC: $rc"
  exit $rc
}

# Setup a trap to catch SIGTERM and relay it to child processes
trap _kill_procs SIGTERM

# Wait for any children to terminate
wait -n

echo "TERMINATING"

# kill remaining processes
_kill_procs
