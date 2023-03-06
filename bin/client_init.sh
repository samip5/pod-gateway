#!/bin/bash

set -ex

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
VXLAN_GATEWAY_IPV6="${VXLAN_IPV6_NETWORK}::1"

function configureIPV6 {
    # For debugging reasons print some info
    echo "Configure IPV6"
    ip -6 addr
    ip -6 route

    ip -6 r del default || /bin/true

    if ping -6 -c 1 -W 1 2001:4860:4860::8888; then
      echo "WE SHOULD NOT BE ABLE TO PING OVER IPV6 -> EXIT"
      exit 255
    fi

    # For debugging reasons print some info
    ip -6 addr
    ip -6 route

    K8S_DNS_IPV6="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
    GATEWAY_IPV6="$(dig AAAA +short "$GATEWAY_NAME" "@${K8S_DNS_IPV6}")"
    STRIPPED_HOSTNAME="$(hostname | cut -d '-' -f 1)"

    NAT6_ENTRY=""
    if [ -f /config/nat6.conf ]; then
        NAT6_ENTRY="$(grep $STRIPPED_HOSTNAME /config/nat6.conf || true)"
    elif [ -f /config/nat.conf ]; then
        NAT6_ENTRY="$(grep $STRIPPED_HOSTNAME /config/nat.conf || true)"
    fi

    # Make sure there is correct route for gateway
    # K8S_GW_IPV6 is not set when script is called again and the route should still exist on the pod anyway.
    if [ -n "$K8S_GW_IPV6" ]; then
        ip -6 route add "$K8S_GW_IPV6" via "$K8S_GW_IPV6"
    fi


    # Create tunnel NIC via IPV6 when IPV4 is disabled
    if [ "$IPV4_ENABLED" == "false" ]; then
      ip link add vxlan0 type vxlan id "$VXLAN_ID" dev eth0 dstport 0 group ff05::100 || true
      bridge fdb append to 00:00:00:00:00:00 dst "$GATEWAY_IPV6"  dev vxlan0
      ip link set up dev vxlan0
    else
      bridge fdb append to 00:00:00:00:00:00 dst "$GATEWAY_IPV6"  dev vxlan0
    fi

    if [[ -z "$NAT6_ENTRY" ]]; then
      echo "Trying to get dynamic IPV6 address"
      dhclient -v -6 vxlan0
      # ip -6 route add default via "$VXLAN_GATEWAY_IPV6"
    else
      IP=$(cut -d' ' -f2 <<< "$NAT6_ENTRY")
      VXLAN_IPV6="${VXLAN_IPV6_NETWORK}::${IP}"
      echo "Use fixed IPV6 $VXLAN_IPV6"
      ip -6 addr add "${VXLAN_IPV6}/64" dev vxlan0
      ip -6 route add default via "$VXLAN_GATEWAY_IPV6"
    fi

    # For debugging reasons print some info
    ip -6 addr
    ip -6 route

    ping6 -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IPV6"
}

function configureIPV4 {
    echo "Configure IPV4"
    ip addr
    ip route

    echo "Dropping default route"
    ip route del 0/0 || /bin/true

    # After this point nothing should be reachable -> check
    if ping -c 1 -W 1000 8.8.8.8; then
      echo "WE SHOULD NOT BE ABLE TO PING -> EXIT"
      exit 255
    fi

    ip addr
    ip route

    K8S_DNS_IP="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
    GATEWAY_IP="$(dig +short "$GATEWAY_NAME" "@${K8S_DNS_IP}")"
    STRIPPED_HOSTNAME="$(hostname | cut -d '-' -f 1)"

    NAT_ENTRY="$(grep $STRIPPED_HOSTNAME /config/nat.conf || true)"

    # Make sure there is correct route for gateway
    # K8S_GW_IP is not set when script is called again and the route should still exist on the pod anyway.
    if [ -n "$K8S_GW_IP" ]; then
        ip route add "$GATEWAY_IP" via "$K8S_GW_IP"
    fi

    # For debugging reasons print some info
    ip addr
    ip route

    ping -c "${CONNECTION_RETRY_COUNT}" "$GATEWAY_IP"
    if [ "$IPV6_ENABLED" == "false" ]; then
      ip link add vxlan0 type vxlan id "$VXLAN_ID" dev eth0 dstport 0 || true
      bridge fdb append to 00:00:00:00:00:00 dst "$GATEWAY_IP" dev vxlan0
    else
      GATEWAY_IPV6="$(dig AAAA +short "$GATEWAY_NAME" "@${K8S_DNS_IP}")"
      ip link add vxlan0 type vxlan id "$VXLAN_ID" dev eth0 dstport 0 group ff05::100|| true
      bridge fdb append to 00:00:00:00:00:00 dst "$GATEWAY_IPV6" dev vxlan0
    fi
    ip link set up dev vxlan0

    # Configure IP and default GW though the gateway docker
    if [[ -z "$NAT_ENTRY" ]]; then
      echo "Get dynamic IP"
      dhclient -v -cf /etc/dhclient.conf vxlan0
    else
      IP=$(cut -d' ' -f2 <<< "$NAT_ENTRY")
      VXLAN_IP="${VXLAN_IP_NETWORK}.${IP}"
      echo "Use fixed IP $VXLAN_IP"
      ip addr add "${VXLAN_IP}/24" dev vxlan0
      route add default gw "$VXLAN_GATEWAY_IP"
    fi

    # For debugging reasons print some info
    ip addr
    ip route

    # Check we can connect to the gateway ussing the vxlan device
    ping -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP"
}

cat << EOF > /etc/dhclient.conf
backoff-cutoff 2;
initial-interval 1;
reboot 0;
retry 10;
select-timeout 0;
timeout 30;
interface "vxlan0"
 {
  request subnet-mask,
          broadcast-address,
          routers;
          #domain-name-servers;
  require routers,
          subnet-mask;
          #domain-name-servers;
 }
EOF

# in re-entry we need to remove the vxlan
# on first entry set a routing rule to the k8s DNS server
if ip addr | grep -q vxlan0; then
  ip link del vxlan0
else
  if [ "$IPV4_ENABLED" == "true" ]; then
    K8S_GW_IP=$(/sbin/ip route | awk '/default/ { print $3 }')
    for local_cidr in $NOT_ROUTED_TO_GATEWAY_CIDRS; do
      # command might fail if rule already set
      ip route add "$local_cidr" via "$K8S_GW_IP" || /bin/true
    done
  fi

  if [ "$IPV6_ENABLED" == "true" ]; then
    K8S_GW_IPV6=$(/sbin/ip -6 route | awk '/default/ { print $3 }')
    if [[ $K8S_GW_IPV6 == fe80:* ]]; then
      K8S_GW_IPV6="$K8S_GW_IPV6%$(/sbin/ip -6 route | awk '/default/ { print $5 }')"
    fi
    for local_cidr in $NOT_ROUTED_TO_GATEWAY_IPV6_CIDRS; do
      ip -6 route add "$local_cidr" via "$K8S_GW_IPV6" || /bin/true
    done
  fi
fi

if [ "$IPV4_ENABLED" == "true" ] && [ "$IPV6_ENABLED" == "true" ]; then
  configureIPV4
  configureIPV6
elif [ "$IPV4_ENABLED" == "true" ] && [ "$IPV6_ENABLED" == "false" ]; then
  configureIPV4
elif [ "$IPV4_ENABLED" == "false" ] && [ "$IPV6_ENABLED" == "true" ]; then
  configureIPV6
fi

echo "Gateway ready and reachable"
