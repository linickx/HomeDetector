#!/usr/bin/with-contenv bashio

for host in $(bashio::config 'resolvers|keys'); do
    server=$(bashio::config "resolvers[${host}].server")
    # Look for & resolve Configured/Enable Home Assisitant Add-Ons
    if echo "$server" | grep -q -E "^[a-z0-9]{5,8}-"; then
        addon_ip=$(dig +short "$server")
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

if [ ! -f /config/opencanary.conf ]; then
    echo "👉🏼 Writing default opencanary.conf"
	cp /etc/opencanaryd/opencanary.conf /config/opencanary.conf
else
    # Copy HomeAssistant Config to opencanary location
    cp /config/opencanary.conf /etc/opencanaryd/opencanary.conf
fi
sleep 1
echo "Starting the HoneyPot (OpenCanary)..."
opencanaryd --start

sleep 1
echo "Starting the DNS Listener..."
python3 /app/listener.py
