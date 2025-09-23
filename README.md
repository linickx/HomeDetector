# Home Detector

A lightweight intrusion detector for Home Assistant

> See [INSTALL.md](docs/INSTALL.md) for installation instructions.
> By default only a Telnet Honeypot is enabled, for more advanced detections see [Docs.md](https://github.com/linickx/ha-addons/blob/main/homedetector/DOCS.md)

#### Related blog posts:
1. [Running Open Canary on Home Assistant](https://www.linickx.com/honeypot-running-open-canary-on-home-assistant)
2. [IoT DNS Anomaly Detection with Home Detector](https://www.linickx.com/iot-dns-anomaly-detection-with-home-detector)

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

## 📝 Admin Stuff 📝

Here are some of the things you can do in the config, an admin web page is provided for monitoring.

* Integrate with Home Assistant Webhooks to send external notifications
* Tune learning to suit your needs, default 30 days DNS observation
* Inject Custom DNS A responses
* Custom upstream DNS resolvers

## 🙏🏻 Thank you 🙏🏻

Thank you world of Open-Source, this project would be nowhere without you. Notable mentions...

* [Michael Irigoyen](https://pictogrammers.com/contributor/mririgoyen/) for the Logo (_Material Design Icon_)
* Paul for publishing [dnslib](https://github.com/paulc/dnslib)
* [OpenCanary](https://opencanary.readthedocs.io/)
* [Mark Otto and team](https://getbootstrap.com/docs/5.3/about/team/) for [Bootstrap](https://getbootstrap.com)
* [文翼 (wenzhixin)](https://github.com/wenzhixin) for [bootstrap-table](https://bootstrap-table.com)
* [Stefan Haack](https://shaack.com) for [bootstrap-auto-darkmode](https://github.com/shaack/bootstrap-auto-dark-mode)
* ..._and anyone else who contributed to the python libraries installed from_ `requirements.txt` 😉
