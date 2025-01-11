#!/bin/bash

set -ex

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

if [ "$IPV6_ENABLED" != "true" ] && [ "$IPV4_ENABLED" != "true" ]; then
  echo "Neither IPV4 nor IPV6 is enabled. Exiting."
  exit 250
fi

# Validate IPv6 gateway if IPv6 is enabled
if [ "$IPV6_ENABLED" == "true" ]; then
  if [ "$VXLAN_GATEWAY_IPV6" == "::1" ]; then
    echo "The IPv6 gateway address seems to be ::1 which is not valid when we want IPv6 support enabled. Exiting."
    exit 255
  fi
fi


if [ "${IPTABLES_NFT:-no}" = "yes" ];then
    # We cannot just call iptables-translate as it'll just print new syntax without applying
    rm /sbin/iptables
    ln -s /sbin/iptables-translate /sbin/iptables
    if [ "$IPV6_ENABLED" == "true" ]; then
        rm -f /sbin/ip6tables
        ln -s /sbin/ip6tables-translate /sbin/ip6tables
    fi
fi

# It might already exists in case initContainer is restarted
if ip addr | grep -q vxlan0; then
  ip link del vxlan0
fi

# Enable IP forwarding based on enabled protocols
if [ "$IPV4_ENABLED" == "true" ] && [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
    sysctl -w net.ipv4.ip_forward=1
fi
if [ "$IPV6_ENABLED" == "true" ] && [[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) -ne 1 ]]; then
    sysctl -w net.ipv6.conf.all.forwarding=1
fi

# Create VXLAN NIC
ip link add vxlan0 type vxlan id $VXLAN_ID dev eth0 dstport "${VXLAN_PORT:-0}" || true
# Configure IP addresses based on enabled protocols
if [ "$IPV4_ENABLED" == "true" ]; then
    VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
    ip addr add ${VXLAN_GATEWAY_IP}/24 dev vxlan0 || true
fi
if [ "$IPV6_ENABLED" == "true" ]; then
    VXLAN_GATEWAY_IPV6="${VXLAN_IPV6_NETWORK}::1"
    ip -6 addr add ${VXLAN_GATEWAY_IPV6}/64 dev vxlan0 || true
fi

ip link set up dev vxlan0

# Handle MTU settings
if [[ -n "$VPN_INTERFACE_MTU" ]]; then
  ETH0_INTERFACE_MTU=$(cat /sys/class/net/eth0/mtu)
  VXLAN_INTERFACE_MAX_MTU=$((ETH0_INTERFACE_MTU-50))
  if [ ${VPN_INTERFACE_MTU} >= ${VXLAN_INTERFACE_MAX_MTU} ];then
    ip link set mtu "${VXLAN_INTERFACE_MAX_MTU}" dev vxlan0
  else
    ip link set mtu "${VPN_INTERFACE_MTU}" dev vxlan0
  fi
fi

# Set routing rules based on enabled protocols
if [ "$IPV4_ENABLED" == "true" ]; then
    if ! ip rule | grep -q "from all lookup main suppress_prefixlength 0"; then
        ip rule add from all lookup main suppress_prefixlength 0 preference 50
    fi
fi
if [ "$IPV6_ENABLED" == "true" ]; then
    if ! ip -6 rule | grep -q "from all lookup main suppress_prefixlength 0"; then
        ip -6 rule add from all lookup main suppress_prefixlength 0 preference 50
    fi
fi

# Enable outbound NAT based on enabled protocols
if [[ -n "$SNAT_IP" ]]; then
    if [ "$IPV4_ENABLED" == "true" ]; then
        echo "Enable IPv4 SNAT"
        iptables -t nat -A POSTROUTING -o "$VPN_INTERFACE" -j SNAT --to "$SNAT_IP"
    fi
    if [ "$IPV6_ENABLED" == "true" ] && [[ -n "$SNAT_IPV6" ]]; then
        echo "Enable IPv6 SNAT"
        ip6tables -t nat -A POSTROUTING -o "$VPN_INTERFACE" -j SNAT --to "$SNAT_IPV6"
    fi
else
    if [ "$IPV4_ENABLED" == "true" ]; then
        echo "Enable IPv4 Masquerading"
        iptables -t nat -A POSTROUTING -j MASQUERADE
    fi
    if [ "$IPV6_ENABLED" == "true" ]; then
        echo "Enable IPv6 Masquerading"
        ip6tables -t nat -A POSTROUTING -j MASQUERADE
    fi
fi

if [[ -n "$VPN_INTERFACE" ]]; then
   # Process IPv4 NAT configuration
   if [ "$IPV4_ENABLED" == "true" ] && [ -f /config/nat.conf ]; then
       while read -r line; do
           [[ $line =~ ^#.* ]] && continue

           echo "Processing IPv4 NAT line: $line"
           NAME=$(cut -d' ' -f1 <<< "$line")
           IP=$(cut -d' ' -f2 <<< "$line")
           PORTS=$(cut -d' ' -f3 <<< "$line")

           for port_string in ${PORTS//,/ }; do
               PORT_TYPE=$(cut -d':' -f1 <<< "$port_string")
               PORT_NUMBER=$(cut -d':' -f2 <<< "$port_string")
               echo "IPv4 NAT: IP: $IP , NAME: $NAME , PORT: $PORT_NUMBER , TYPE: $PORT_TYPE"

               iptables -t nat -A PREROUTING -p "$PORT_TYPE" -i "$VPN_INTERFACE" \
                        --dport "$PORT_NUMBER" -j DNAT \
                        --to-destination "${VXLAN_IP_NETWORK}.${IP}:${PORT_NUMBER}"

               iptables -A FORWARD -p "$PORT_TYPE" -d "${VXLAN_IP_NETWORK}.${IP}" \
                        --dport "$PORT_NUMBER" -m state --state NEW,ESTABLISHED,RELATED \
                        -j ACCEPT
           done
       done </config/nat.conf
   fi

   # Process IPv6 NAT configuration
   if [ "$IPV6_ENABLED" == "true" ] && [ -f /config/nat6.conf ]; then
       while read -r line; do
           [[ $line =~ ^#.* ]] && continue

           echo "Processing IPv6 NAT line: $line"
           NAME=$(cut -d' ' -f1 <<< "$line")
           IPV6=$(cut -d' ' -f2 <<< "$line")
           PORTS=$(cut -d' ' -f3 <<< "$line")

           for port_string in ${PORTS//,/ }; do
               PORT_TYPE=$(cut -d':' -f1 <<< "$port_string")
               PORT_NUMBER=$(cut -d':' -f2 <<< "$port_string")
               echo "IPv6 NAT: IPv6: $IPV6 , NAME: $NAME , PORT: $PORT_NUMBER , TYPE: $PORT_TYPE"

               ip6tables -t nat -A PREROUTING -p "$PORT_TYPE" -i "$VPN_INTERFACE" \
                         --dport "$PORT_NUMBER" -j DNAT \
                         --to-destination "[${IPV6}]:${PORT_NUMBER}"

               ip6tables -A FORWARD -p "$PORT_TYPE" -d "${IPV6}" \
                         --dport "$PORT_NUMBER" -m state --state NEW,ESTABLISHED,RELATED \
                         -j ACCEPT
           done
       done </config/nat6.conf
   fi

     # Configure protocol-specific rules
    if [ "$IPV4_ENABLED" == "true" ]; then
        echo "Allow IPv4 DHCP traffic from vxlan"
        iptables -A INPUT -i vxlan0 -p udp --sport=68 --dport=67 -j ACCEPT
        iptables -A FORWARD -i "$VPN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -i "$VPN_INTERFACE" -j REJECT
    fi

    if [ "$IPV6_ENABLED" == "true" ]; then
        # Allow DHCPv6 client traffic
        ip6tables -A INPUT -i vxlan0 -p udp --dport 546 -j ACCEPT
        ip6tables -A INPUT -i vxlan0 -p udp --dport 547 -j ACCEPT
        ip6tables -A INPUT -p icmpv6 -j ACCEPT
        ip6tables -A FORWARD -p icmpv6 -j ACCEPT
        ip6tables -A FORWARD -i "$VPN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A FORWARD -i "$VPN_INTERFACE" -j REJECT
    fi

    if [[ $VPN_BLOCK_OTHER_TRAFFIC == true ]] ; then
        # Apply blocking rules based on enabled protocols
        if [ "$IPV4_ENABLED" == "true" ]; then
            iptables --policy FORWARD DROP
            iptables -I FORWARD -o "$VPN_INTERFACE" -j ACCEPT
            iptables --policy OUTPUT DROP
            iptables -A OUTPUT -p udp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT
            iptables -A OUTPUT -p tcp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT
            iptables -A OUTPUT -o "$VPN_INTERFACE" -j ACCEPT
            iptables -A OUTPUT -o vxlan0 -j ACCEPT
        fi

        if [ "$IPV6_ENABLED" == "true" ]; then
            ip6tables --policy FORWARD DROP
            ip6tables -I FORWARD -o "$VPN_INTERFACE" -j ACCEPT
            ip6tables --policy OUTPUT DROP
            ip6tables -A OUTPUT -p udp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT
            ip6tables -A OUTPUT -p tcp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT
            ip6tables -A OUTPUT -o "$VPN_INTERFACE" -j ACCEPT
            ip6tables -A OUTPUT -o vxlan0 -j ACCEPT
        fi

        # Configure local network routes based on protocol
        for local_cidr in $VPN_LOCAL_CIDRS; do
            if [[ $local_cidr =~ ":" ]]; then
                if [ "$IPV6_ENABLED" == "true" ]; then
                    K8S_GW_IPV6=$(/sbin/ip -6 route | awk '/default/ { print $3 }')
                    ip -6 route add "$local_cidr" via "$K8S_GW_IPV6" || true
                    ip6tables -A OUTPUT -d "$local_cidr" -j ACCEPT
                fi
            else
                if [ "$IPV4_ENABLED" == "true" ]; then
                    K8S_GW_IP=$(/sbin/ip route | awk '/default/ { print $3 }')
                    ip route add "$local_cidr" via "$K8S_GW_IP" || true
                    iptables -A OUTPUT -d "$local_cidr" -j ACCEPT
                fi
            fi
        done
    fi
fi