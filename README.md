# Home Detector

A lightweight intrusion detector for Home Assistant

## 🔥 DNS Anomaly Detection for IoT Devices 🔥

Setup dedicated monitoring scopes for your home IOT devices and track their DNS usage.

*  Alert when IoT devices contact new domains
* _Optional_ Alert when IoT devices contact new hosts
* _Optional_ blocks, return `NXDOMAIN` for unusual requests

## 🍯 Honeypot 🍯

Additional log-in detections for your home network! 

* Telnet Honeypot enabled by default
* _Optional_ HTTP (NAS Web Page) HoneyPot
* _Optional_ FTP HoneyPot

## Admin Stuff...

* Integrate with Home Assistant Webhooks to send external notifications
* Tune learning to suit your needs, default 30days DNS observation
* Inject Custom DNS A responses
* Custom upstream DNS resolvers
