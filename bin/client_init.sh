#!/bin/bash

set -ex

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

# Handle hostnames in K8s pod environments
if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
    # In Kubernetes, extract the base pod name before the first dash
    HOSTNAME_REAL=$(hostname | cut -d'-' -f1)
else
    # In Docker or other environments, use the full hostname
    HOSTNAME_REAL=$(hostname)
fi
echo $HOSTNAME_REAL

# Determine cluster networking mode
if [ "$IPV4_ENABLED" == "true" ] && [ "$IPV6_ENABLED" == "true" ]; then
    CLUSTER_MODE="dual-stack"
elif [ "$IPV4_ENABLED" == "true" ]; then
    CLUSTER_MODE="ipv4-only"
elif [ "$IPV6_ENABLED" == "true" ]; then
    CLUSTER_MODE="ipv6-only"
else
    echo "No IP protocol enabled. Exiting."
    exit 250
fi

echo "Operating in $CLUSTER_MODE mode"

# Handle existing vxlan interface and set initial routes
if ip addr | grep -q vxlan0; then
    ip link del vxlan0
else
    case $CLUSTER_MODE in
        "ipv4-only")
            K8S_GW_IP=$(/sbin/ip route | awk '/default/ { print $3 }')
            ;;
        "ipv6-only")
            K8S_GW_IPV6=$(/sbin/ip -6 route | awk '/default/ { print $3 }')
            ;;
        "dual-stack")
            K8S_GW_IP=$(/sbin/ip route | awk '/default/ { print $3 }')
            K8S_GW_IPV6=$(/sbin/ip -6 route | awk '/default/ { print $3 }')
            ;;
    esac
fi

# Resolve gateway address(es) based on cluster mode
case $CLUSTER_MODE in
    "ipv4-only")
        K8S_DNS_IP="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
        GATEWAY_IP="$(dig +short "$GATEWAY_NAME" "@${K8S_DNS_IP}")"
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat.conf || true)"
        VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
        LOCAL_IP=$(ip -4 addr show eth0 | awk '/inet / {split($2,a,"/"); print a[1]}' | head -n1)
        # Add route to gateway if K8S_GW_IP is available
        [ -n "$K8S_GW_IP" ] && ip route add "$GATEWAY_IP" via "$K8S_GW_IP" || true
        ;;
    "ipv6-only")
        K8S_DNS_IPV6="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
        GATEWAY_IP="$(dig +short AAAA "$GATEWAY_NAME" "@[${K8S_DNS_IPV6}]")"
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat6.conf || true)"
        VXLAN_GATEWAY_IP="${VXLAN_IPV6_NETWORK}::1"
        LOCAL_IP=$(ip -6 addr show eth0 | awk '/inet6 / {split($2,a,"/"); print a[1]}' | grep -v '^fe80' | head -n1)
        # Add route to gateway if K8S_GW_IPV6 is available
        [ -n "$K8S_GW_IPV6" ] && ip -6 route add "$GATEWAY_IP" via "$K8S_GW_IPV6" || true
        ;;
    "dual-stack")
        K8S_DNS_IP="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
        K8S_DNS_IPV6="$(cut -d ' ' -f 1 <<< "$K8S_DNS_IPS")"
        GATEWAY_IP="$(dig +short "$GATEWAY_NAME" "@${K8S_DNS_IP}")"
        GATEWAY_IPV6="$(dig +short AAAA "$GATEWAY_NAME" "@${K8S_DNS_IP}")"
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat.conf || true)"
        NAT_ENTRY_V6="$(grep "^$HOSTNAME_REAL " /config/nat6.conf || true)"
        VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
        VXLAN_GATEWAY_IPV6="${VXLAN_IPV6_NETWORK}::1"
        LOCAL_IP=$(ip -4 addr show eth0 | awk '/inet / {split($2,a,"/"); print a[1]}' | head -n1)
        # Add routes to gateways if available
        [ -n "$K8S_GW_IP" ] && ip route add "$GATEWAY_IP" via "$K8S_GW_IP" || true
        [ -n "$K8S_GW_IPV6" ] && ip -6 route add "$GATEWAY_IPV6" via "$K8S_GW_IPV6" || true
        ;;
esac

# Create VXLAN interface
ip link add vxlan0 type vxlan id "$VXLAN_ID" dev eth0 dstport "${VXLAN_PORT:-0}" || true

# Configure FDB based on mode
case $CLUSTER_MODE in
    "ipv4-only")
        bridge fdb append 00:00:00:00:00:00 dst "$GATEWAY_IP" dev vxlan0
        ;;
    "ipv6-only")
        bridge fdb append 00:00:00:00:00:00 dst "$GATEWAY_IPV6" dev vxlan0
        ;;
    "dual-stack")
        bridge fdb append 00:00:00:00:00:00 dst "$GATEWAY_IP" dev vxlan0
        ;;
esac

ip link set up dev vxlan0

# Configure MTU if specified
if [[ -n "$VPN_INTERFACE_MTU" ]]; then
    ETH0_INTERFACE_MTU=$(cat /sys/class/net/eth0/mtu)
    VXLAN0_INTERFACE_MAX_MTU=$((ETH0_INTERFACE_MTU-50))
    if [ ${VPN_INTERFACE_MTU} >= ${VXLAN0_INTERFACE_MAX_MTU} ];then
        ip link set mtu "${VXLAN0_INTERFACE_MAX_MTU}" dev vxlan0
    else
        ip link set mtu "${VPN_INTERFACE_MTU}" dev vxlan0
    fi
fi

cat << EOF > /etc/dhclient4.conf
backoff-cutoff 2;
initial-interval 1;
reboot 0;
retry 10;
select-timeout 0;
timeout 30;

interface "vxlan0" {
    send interface-mtu 1450;
    request subnet-mask,
            broadcast-address,
            routers;
    require routers,
            subnet-mask;
}
EOF

# Create IPv6 dhclient config
cat << EOF > /etc/dhclient6.conf
backoff-cutoff 2;
initial-interval 1;
reboot 0;
retry 10;
select-timeout 0;
timeout 30;

interface "vxlan0" {
    request dhcp6.name-servers;
    send dhcp6.ia-na 0;
}
EOF


# Configure IP addresses based on mode
case $CLUSTER_MODE in
    "ipv4-only")
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat.conf || true)"
        if [[ -z "$NAT_ENTRY" ]]; then
            killall -q dhclient || true
            dhclient -4 -v -cf /etc/dhclient4.conf vxlan0
        else
            IP=$(cut -d' ' -f2 <<< "$NAT_ENTRY")
            ip addr add "${VXLAN_IP_NETWORK}.${IP}/24" dev vxlan0
            ip route add default via "${VXLAN_IP_NETWORK}.1"
        fi
        ;;
    "ipv6-only")
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat6.conf || true)"
        if [[ -z "$NAT_ENTRY" ]]; then
            killall -q dhclient || true
            dhclient -6 -v -cf /etc/dhclient6.conf vxlan0
        else
            IPV6=$(cut -d' ' -f2 <<< "$NAT_ENTRY")
            ip -6 addr add "${IPV6}/64" dev vxlan0
            ip -6 route add default via "${VXLAN_IPV6_NETWORK}::1"
        fi
        ;;
    "dual-stack")
        NAT_ENTRY="$(grep "^$HOSTNAME_REAL " /config/nat.conf || true)"
        NAT_ENTRY_V6="$(grep "^$HOSTNAME_REAL " /config/nat6.conf || true)"

        if [[ -z "$NAT_ENTRY" ]] && [[ -z "$NAT_ENTRY_V6" ]]; then
            killall -q dhclient || true
            # Run dhclient separately for IPv4 and IPv6
            dhclient -4 -v -cf /etc/dhclient4.conf vxlan0
            dhclient -6 -v -cf /etc/dhclient6.conf vxlan0
        else
            if [[ -n "$NAT_ENTRY" ]]; then
                IP=$(cut -d' ' -f2 <<< "$NAT_ENTRY")
                ip addr add "${VXLAN_IP_NETWORK}.${IP}/24" dev vxlan0
                ip route add default via "${VXLAN_IP_NETWORK}.1"
            fi
            if [[ -n "$NAT_ENTRY_V6" ]]; then
                IPV6=$(cut -d' ' -f2 <<< "$NAT_ENTRY_V6")
                ip -6 addr add "${IPV6}/64" dev vxlan0
                ip -6 route add default via "${VXLAN_IPV6_NETWORK}::1"
            fi
        fi
        ;;
esac

# Verify connectivity based on mode
case $CLUSTER_MODE in
    "ipv4-only")
        ping -c "${CONNECTION_RETRY_COUNT}" "${VXLAN_IP_NETWORK}.1" || exit 254
        ;;
    "ipv6-only")
        ping6 -c "${CONNECTION_RETRY_COUNT}" "${VXLAN_IPV6_NETWORK}::1" || exit 254
        ;;
    "dual-stack")
        ping -c "${CONNECTION_RETRY_COUNT}" "${VXLAN_IP_NETWORK}.1" || exit 254
        ping6 -c "${CONNECTION_RETRY_COUNT}" "${VXLAN_IPV6_NETWORK}::1" || exit 254
        ;;
esac

echo "Gateway ready and reachable"
