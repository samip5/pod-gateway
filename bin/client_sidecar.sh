#!/bin/bash
set -e

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

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

# Set gateway IPs based on mode
case $CLUSTER_MODE in
    "ipv4-only")
        VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
        ;;
    "ipv6-only")
        VXLAN_GATEWAY_IP="${VXLAN_IPV6_NETWORK}::1"
        ;;
    "dual-stack")
        VXLAN_GATEWAY_IP4="${VXLAN_IP_NETWORK}.1"
        VXLAN_GATEWAY_IP6="${VXLAN_IPV6_NETWORK}::1"
        ;;
esac

# Loop to test connection to gateway each 10 seconds
# If connection fails then reset connection
while true; do
    case $CLUSTER_MODE in
        "ipv4-only")
            echo "Monitor connection to $VXLAN_GATEWAY_IP"
            ping -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP" > /dev/null || break
            ;;
        "ipv6-only")
            echo "Monitor connection to $VXLAN_GATEWAY_IP"
            ping6 -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP" > /dev/null || break
            ;;
        "dual-stack")
            echo "Monitor connection to $VXLAN_GATEWAY_IP4 and $VXLAN_GATEWAY_IP6"
            if ! ping -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP4" > /dev/null || \
               ! ping6 -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP6" > /dev/null; then
                break
            fi
            ;;
    esac

    # Sleep while reacting to signals
    sleep 10 &
    wait $!
done

echo
echo
echo "Reconnecting to ${GATEWAY_NAME}"

# reconnect
client_init.sh
