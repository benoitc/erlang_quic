#!/bin/bash
set -e

# Wait for interfaces to be ready
sleep 2

echo "=== NAT Gateway Interface Detection ==="
echo "Available interfaces:"
ip -4 addr show

# Find all non-loopback interfaces (strip @ifXXX suffix from veth interfaces)
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | grep -v '^tunl0$' | grep -v '^sit0$' | grep -v '^ip6tnl0$')

echo "Detected interfaces: $INTERFACES"

# Determine external vs internal interface
# External: has a route to 0.0.0.0/0 or to the Docker default gateway
# Internal: no default route (internal Docker network)

DEFAULT_ROUTE_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)
echo "Default route interface: $DEFAULT_ROUTE_IF"

# External interface is the one with default route
EXT_IF="$DEFAULT_ROUTE_IF"

# Internal interface is the other one (not lo, not external)
INT_IF=""
for iface in $INTERFACES; do
    if [ "$iface" != "$EXT_IF" ] && [ "$iface" != "lo" ]; then
        INT_IF="$iface"
        break
    fi
done

# If no internal interface found, fall back to second interface
if [ -z "$INT_IF" ]; then
    for iface in $INTERFACES; do
        if [ "$iface" != "$EXT_IF" ]; then
            INT_IF="$iface"
            break
        fi
    done
fi

echo "=== NAT Gateway Configuration ==="
echo "External interface: $EXT_IF"
echo "Internal interface: $INT_IF"

# Validate we have both interfaces
if [ -z "$EXT_IF" ] || [ -z "$INT_IF" ]; then
    echo "ERROR: Could not detect both interfaces"
    echo "EXT_IF=$EXT_IF INT_IF=$INT_IF"
    exit 1
fi

# Get IP addresses
EXT_IP=$(ip -4 addr show "$EXT_IF" | awk '/inet / {split($2, a, "/"); print a[1]}')
INT_IP=$(ip -4 addr show "$INT_IF" | awk '/inet / {split($2, a, "/"); print a[1]}')
INT_NET=$(ip -4 route | grep "$INT_IF" | grep -v default | awk '{print $1}' | head -1)

echo "External IP: $EXT_IP"
echo "Internal IP: $INT_IP"
echo "Internal Network: $INT_NET"

# IP forwarding is set via docker-compose sysctls
echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# NAT masquerade for outbound traffic
iptables -t nat -A POSTROUTING -o "$EXT_IF" -j MASQUERADE

# Allow forwarding between interfaces
iptables -A FORWARD -i "$INT_IF" -o "$EXT_IF" -j ACCEPT
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Create miniupnpd chains
iptables -t nat -N MINIUPNPD 2>/dev/null || iptables -t nat -F MINIUPNPD
iptables -t nat -N MINIUPNPD-POSTROUTING 2>/dev/null || iptables -t nat -F MINIUPNPD-POSTROUTING
iptables -t filter -N MINIUPNPD 2>/dev/null || iptables -t filter -F MINIUPNPD

# Insert jumps to miniupnpd chains
iptables -t nat -A PREROUTING -i "$EXT_IF" -j MINIUPNPD
iptables -t nat -A POSTROUTING -o "$EXT_IF" -j MINIUPNPD-POSTROUTING
iptables -t filter -A FORWARD -i "$EXT_IF" ! -o "$EXT_IF" -j MINIUPNPD

echo "iptables configured"

# Update miniupnpd config with actual interface names
sed -i "s/^ext_ifname=.*/ext_ifname=$EXT_IF/" /etc/miniupnpd/miniupnpd.conf
sed -i "s/^listening_ip=.*/listening_ip=$INT_IF/" /etc/miniupnpd/miniupnpd.conf

# Note: Don't update ext_ip - we use a fake public IP (203.0.113.42) for testing
# since miniupnpd ignores private IP addresses as external IPs.
# The nat library will query this fake IP, but actual traffic uses Docker networking.
echo "Using fake external IP from config (for miniupnpd compatibility)"

# Add allow rule for internal network if not present
if [ -n "$INT_NET" ] && ! grep -q "allow .* $INT_NET" /etc/miniupnpd/miniupnpd.conf; then
    echo "allow 1024-65535 $INT_NET 1024-65535" >> /etc/miniupnpd/miniupnpd.conf
fi

echo "=== Starting miniupnpd ==="
cat /etc/miniupnpd/miniupnpd.conf

# Start miniupnpd in foreground with debug
exec miniupnpd -d -f /etc/miniupnpd/miniupnpd.conf -i "$EXT_IF" -a "$INT_IF"
