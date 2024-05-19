#!/usr/bin/with-contenv bashio

for host in $(bashio::config 'resolvers|keys'); do
    server=$(bashio::config "resolvers[${host}].server")
    # Look for & resolve Configured/Enable Home Assisitant Add-Ons
    if echo "$server" | grep -q -E "^local-"; then
        addon_ip=$(dig +short local-dnscrypt-proxy)
        addon_port=$(bashio::config "resolvers[${host}].port")
        echo "$server ($addon_port) is an Addon -> $addon_ip"
        export "${server//"-"}"="$addon_ip"
    fi
done

echo "Starting the DNS Listener..."
python3 /listener.py
