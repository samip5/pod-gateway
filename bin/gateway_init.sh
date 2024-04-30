#!/bin/bash

set -ex

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
VXLAN_GATEWAY_IPV6="${VXLAN_IPV6_NETWORK}::1"

if [ "$IPV6_ENABLED" != "true" ] && [ "$IPV4_ENABLED" != "true" ]; then
  echo "Neither IPV4 nor IPV6 is enabled. Exiting."
  exit 255
fi

if [ "$VXLAN_GATEWAY_IPV6" == "::1" ] && [ "$IPV6_ENABLED" == "true" ]; then
  echo "The IPv6 gateway address seems to be ::1 which is not valid when we want IPv6 support enabled. Exiting."
  exit 255
fi

if [ "${IPTABLES_NFT:-no}" = "yes" ];then
    # We cannot just call iptables-translate as it'll just print new syntax without applying
    rm /sbin/iptables
    ln -s /sbin/iptables-translate /sbin/iptables
fi

# It might already exists in case initContainer is restarted
if ip addr | grep -q vxlan0; then
  ip link del vxlan0
fi



if [ "$IPV4_ENABLED" == "true" ]; then
  # Enable IP forwarding
  if [[ $(cat /proc/sys/net/ipv4/ip_forward) -ne 1 ]]; then
      echo "ip_forward is not enabled; enabling."
      sysctl -w net.ipv4.ip_forward=1
  fi

  if [ "$IPV6_ENABLED" == "true" ]; then
    # Create VXLAN NIC over IPv6
    ip link add vxlan0 type vxlan id $VXLAN_ID dev eth0 dstport 0 group ff05::100 || true
  else
    # Create VXLAN NIC over IPv4
    ip link add vxlan0 type vxlan id $VXLAN_ID dev eth0 dstport 0 || true
  fi
  ip addr add ${VXLAN_GATEWAY_IP}/24 dev vxlan0 || true

  # check if rule already exists (retry)
  if ! ip rule | grep -q "from all lookup main suppress_prefixlength 0"; then
    # Set proper firewall rule preference
    ip rule add from all lookup main suppress_prefixlength 0 preference 50;
  fi

  # Enable outbound NAT
  iptables -t nat -A POSTROUTING -j MASQUERADE
fi

if [ "$IPV6_ENABLED" == "true" ]; then
  # Enable IPV6 forwarding
  if [[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) -ne 1 ]]; then
      echo "ipv6.conf.all.forwarding is not enabled; enabling."
      sysctl -w net.ipv6.conf.all.forwarding=1
  fi

  # The logic here is that if we have dual-stack scenario only add the IPv6 address,
  # otherwise we need to create the tunnel here too.
  if [ "$IPV4_ENABLED" == "false" ]; then
    ip link add vxlan0 type vxlan id $VXLAN_ID dev eth0 dstport 0 group ff05::100 || true
    ip -6 addr add ${VXLAN_GATEWAY_IPV6}/64 dev vxlan0 || true
  else
   ip -6 addr add ${VXLAN_GATEWAY_IPV6}/64 dev vxlan0 || true
  fi
  ip link set up dev vxlan0

  # Check if rule already exists (retry, IPV6)
  if ! ip -6 rule | grep -q "from all lookup main suppress_prefixlength 0"; then
    ip -6 rule add from all lookup main suppress_prefixlength 0 preference 50;
  fi

  # Enable outbound NAT
  ip6tables -t nat -A POSTROUTING -j MASQUERADE
fi

if [[ -n "$VPN_INTERFACE" ]]; then
  # Process nat.conf and nat6.conf
  NAT_FILES=()

  if [ "$IPV4_ENABLED" == "true" ]; then
    if [[ -f /config/nat.conf ]]; then
      cat /config/nat.conf
      NAT_FILES+=("IPV4:/config/nat.conf")
    fi
  fi

  if [ "$IPV6_ENABLED" == "true" ]; then
    if [[ -f /config/nat6.conf ]]; then
      cat /config/nat6.conf
      NAT_FILES+=("IPV6:/config/nat6.conf")
    else
      if [[ -f /config/nat.conf ]]; then
        echo "nat6.conf not found, but nat.conf exists. Using nat.conf for IPV6 as well."
        NAT_FILES+=("IPV6:/config/nat.conf")
      fi
    fi
  fi

  for protocol_nat_file_descriptor in $NAT_FILES; do
    protocol=$(cut -d':' -f1 <<< "$protocol_nat_file_descriptor")
    nat_file=$(cut -d':' -f2 <<< "$protocol_nat_file_descriptor")

    # Open inbound NAT ports in nat.conf or nat6.conf
    while read -r line; do
      # Skip lines with comments
      [[ $line =~ ^#.* ]] && continue

      echo "Processing line: $line"
      NAME=$(cut -d' ' -f1 <<< "$line")
      IP=$(cut -d' ' -f2 <<< "$line")
      PORTS=$(cut -d' ' -f3 <<< "$line")

      # Add NAT entries
      for port_string in ${PORTS//,/ }; do
        PORT_TYPE=$(cut -d':' -f1 <<< "$port_string")
        PORT_NUMBER=$(cut -d':' -f2 <<< "$port_string")
        echo "IP: $IP , NAME: $NAME , PORT: $PORT_NUMBER , TYPE: $PORT_TYPE"

        if [[ "$protocol" == "IPV4" ]]; then
          iptables  -t nat -A PREROUTING -p "$PORT_TYPE" -i "$VPN_INTERFACE" \
                    --dport "$PORT_NUMBER"  -j DNAT \
                    --to-destination "${VXLAN_IP_NETWORK}.${IP}:${PORT_NUMBER}"

          iptables  -A FORWARD -p "$PORT_TYPE" -d "${VXLAN_IP_NETWORK}.${IP}" \
                    --dport "$PORT_NUMBER" -m state --state NEW,ESTABLISHED,RELATED \
                    -j ACCEPT
        else
          ip6tables  -t nat -A PREROUTING -p "$PORT_TYPE" -i "$VPN_INTERFACE" \
                    --dport "$PORT_NUMBER"  -j DNAT \
                    --to-destination "[${VXLAN_IPV6_NETWORK}::${IP}]:${PORT_NUMBER}"

          ip6tables  -A FORWARD -p "$PORT_TYPE" -d "${VXLAN_IPV6_NETWORK}::${IP}" \
                    --dport "$PORT_NUMBER" -m state --state NEW,ESTABLISHED,RELATED \
                    -j ACCEPT
        fi
      done
    done <"$nat_file"
  done

  echo "Setting iptables for VPN with NIC ${VPN_INTERFACE}"

    # Firewall incomming traffic from VPN
    echo "Accept traffic alredy ESTABLISHED"

    if [ "$IPV4_ENABLED" == "true" ]; then
      iptables -A FORWARD -i "$VPN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "$VPN_INTERFACE" -j REJECT
    fi

    if [ "$IPV6_ENABLED" == "true" ]; then
      ip6tables -A FORWARD -i "$VPN_INTERFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      # Required by IPV6 spec
      ip6tables -A FORWARD -p ipv6-icmp -j ACCEPT
    fi

    # Reject other traffic"
    if [[ $VPN_BLOCK_OTHER_TRAFFIC == true ]] ; then
      if [ "$IPV4_ENABLED" == "true" ]; then
        # Do not forward any traffic that does not leave through ${VPN_INTERFACE}
        # The openvpn will also add drop rules but this is to ensure we block even if VPN is not connecting
        iptables --policy FORWARD DROP
        iptables -I FORWARD -o "$VPN_INTERFACE" -j ACCEPT


        # Do not allow outbound traffic on eth0 beyond VPN and local traffic
        iptables --policy OUTPUT DROP

        iptables -A OUTPUT -p udp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT #VPN traffic over UDP
        iptables -A OUTPUT -p tcp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT #VPN traffic over TCP

        # Allow local traffic
        for local_cidr in $VPN_LOCAL_CIDRS; do
          iptables -A OUTPUT -d "$local_cidr" -j ACCEPT
        done

        # Allow output for VPN and VXLAN
        iptables -A OUTPUT -o "$VPN_INTERFACE" -j ACCEPT
        iptables -A OUTPUT -o vxlan0 -j ACCEPT
      fi

      if [ "$IPV6_ENABLED" == "true" ]; then
        ip6tables --policy FORWARD DROP
        ip6tables -I FORWARD -o "$VPN_INTERFACE" -j ACCEPT
        # Required by IPv6 spec
        ip6tables -A FORWARD -p ipv6-icmp -j ACCEPT
        ip6tables --policy OUTPUT DROP

        ip6tables -A OUTPUT -p udp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT #VPN traffic over UDP
        ip6tables -A OUTPUT -p tcp --dport "$VPN_TRAFFIC_PORT" -j ACCEPT #VPN traffic over TCP

        for local_cidr in $VPN_LOCAL_IPV6_CIDRS; do
          ip6tables -A OUTPUT -d "$local_cidr" -j ACCEPT
        done

        ip6tables -A OUTPUT -o "$VPN_INTERFACE" -j ACCEPT
        ip6tables -A OUTPUT -o vxlan0 -j ACCEPT
      fi
    fi

    if [ "$IPV4_ENABLED" == "true" ]; then
      #Routes for local networks
      K8S_GW_IP=$(/sbin/ip route | awk '/default/ { print $3 }')
      for local_cidr in $VPN_LOCAL_CIDRS; do
        # command might fail if rule already set
        ip route add "$local_cidr" via "$K8S_GW_IP" || /bin/true
      done
    fi

    if [ "$IPV6_ENABLED" == "true" ]; then
      K8S_GW_IPV6=$(/sbin/ip -6 route | awk '/default/ { print $3 }')
      echo "IPv6 GW is: $K8S_GW_IPV6"
      if [[ $K8S_GW_IPV6 == fe80:* ]]; then
        K8S_GW_IPV6="$K8S_GW_IPV6%$(/sbin/ip -6 route | awk '/default/ { print $5 }')"
      fi
      for local_cidr in $VPN_LOCAL_IPV6_CIDRS; do
        ip -6 route add "$local_cidr" via "$K8S_GW_IPV6" || /bin/true
      done
    fi
  fi

