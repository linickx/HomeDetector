#!/usr/bin/with-contenv bashio

for host in $(bashio::config 'resolvers|keys'); do
    server=$(bashio::config "resolvers[${host}].server")
    # Look for & resolve Configured/Enable Home Assisitant Add-Ons
    if echo "$server" | grep -q -E "^local-"; then
        addon_ip=$(dig +short local-dnscrypt-proxy)
        addon_port=$(bashio::config "resolvers[${host}].port")
        if [ -n "$addon_ip" ]; then
            echo "$server ($addon_port) is an Addon -> $addon_ip"
            export "${server//"-"}"="$addon_ip"
        else
            echo "$server failed to resolve, try restarting the add-on"
        fi
    fi
done

echo "Starting the Admin Web Server..."
python3 /app/web.py &
sleep 1
echo "Starting the HoneyPot (OpenCanary)..."
opencanaryd --start
echo "Starting the DNS Listener..."
python3 /app/listener.py
