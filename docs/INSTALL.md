# Installation Instructions

By installing Home Detector, and performing no configuration at all you will have successfully deployed a Telnet honeypot onto your network which will alert when a threat tries to log in. For more advanced detections see [Docs.md](https://github.com/linickx/ha-addons/blob/main/homedetector/DOCS.md)

## Install via Add-on Store (with custom repository)

Home Detector can be installed via Home Assistant's Add-on Store, to update your store either use the one-click or manually add the repository.

![Screenshot of LINICKX Addons](https://github.com/linickx/ha-addons/blob/main/img/ha-repo.png?raw=true)

### One Click

The button below uses https://my.home-assistant.io to add my repository to your store, if you have not use my.home-assistant URLs before, the first time you visit it will ask for your Home Assistant URL, change if necessary, this is then stored as a cookie for future use.

[![Add Nicks LINICKX repository too your Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Flinickx%2Fha-addons)


### Manually Add the repository

If you'd rather do it manually, on your Home Assistant perform the following:

1. Settings -> Add-ons -> ADD-ON STORE
2. In the top right, select _Repositories_
3. Add https://github.com/linickx/ha-addons

### Scroll Down and Install

The `LINICKX HA Add-ons` will appear at the bottom of the Add-on Store once the above steps have been completed.

Select _Home Detector_ and ___INSTALL___:

![Screenshot of LINICKX Addons](https://github.com/linickx/ha-addons/blob/main/img/linickx-addons.png?raw=true)

## Install Manually (with SCP)

If you'd rather download the code and install that way:

1. Before you start, SSH onto your home assistant and create directory `/addons/homedetector`
2. Download the [latest.zip](https://github.com/linickx/HomeDetector/archive/refs/heads/main.zip)
3. Unzip
4. Copy the contents of `homedetector-main` to `/addons/homedetector`. e.g. `scp -r ./homedetector-main/* root@homeassistant.local:/addons/homedetector/`
5. On the Home Assistant Web GUI: Settings -> Add-ons -> ADD-ON STORE
6. In the top right, select _Check for Updates_
7. Refresh the page/browser
8. Select _Home Detector_ and ___INSTALL___

## Any Other Business

🚨 Warning: Home Detector is only support on 64bit processors, i.e. x86_64 (`amd64`) or ARM64 (`aarch64`) this is due to modern cryptography libraries (_used by Open Canary_) requiring rust which is not provided in the base python/alpine 32bit docker images. For Raspberry Pi users, that means Pi 4 or newer.
