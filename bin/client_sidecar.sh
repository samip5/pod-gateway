#!/bin/bash
set -e

# Load main settings
cat /default_config/settings.sh
. /default_config/settings.sh
cat /config/settings.sh
. /config/settings.sh

VXLAN_GATEWAY_IP="${VXLAN_IP_NETWORK}.1"
VXLAN_GATEWAY_IPV6="${VXLAN_IPV6_NETWORK}::1"

function monitorGateway() {
  if [ "$IPV4_ENABLED" == "true" ]; then
    echo "Monitor connection to $VXLAN_GATEWAY_IP"

    # Test if vxlan is up over IPV4
    ping -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IP" > /dev/null
    IPV4_RESULT="$?"
  else
    IPV4_RESULT="0"
  fi

  if [ "$IPV6_ENABLED" == "true" ]; then
    echo "Monitor connection to $VXLAN_GATEWAY_IPV6"

    # Test if vxlan is up over IPV4
    ping -6 -c "${CONNECTION_RETRY_COUNT}" "$VXLAN_GATEWAY_IPV6" > /dev/null
    IPV6_RESULT="$?"
  else
    IPV6_RESULT="0"
  fi

  if [[ $IPV4_RESULT -ne "0" ]]; then
    echo "Connection to $VXLAN_GATEWAY_IP failed"
    return 255
  fi

  if [[ $IPV6_RESULT -ne "0" ]]; then
    echo "Connection to $VXLAN_GATEWAY_IPV6 failed"
    return 255
  fi

  return 0
}

# Loop to test connection to gateway each 10 seconds
# If connection fails then reset connection
while true; do

  # Ping the gateway vxlan IP -> this only works when vxlan is up
  while monitorGateway; do
    # Sleep while reacting to signals
    sleep 10 &
    wait $!
  done

  echo
  echo
  echo "Reconnecting to ${GATEWAY_NAME}"

  # reconnect
  client_init.sh
done
