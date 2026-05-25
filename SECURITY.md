# Security

## 📩 Contact

To report a security issue, contact me via my website [linickx.com](https://www.linickx.com) or Mastodon [@linickx@infosec.exchange](https://infosec.exchange/@linickx)

## 🔎 Software Bill of Materials

For transparency of the Docker Image contents, and SBOM is now attached to new releases.

## 🔒AppArmor

HomeDetector implements an AppArmor security profile (`apparmor.txt`) to restrict system access and provide defense-in-depth. The profile:

- Limits network access to required ports for DNS (53), web UI (8099), and honeypot services
- Restricts file system access to configuration (`/config/`, `/data/`) and application directories
- Grants only necessary Linux capabilities (CAP_NET_BIND_SERVICE, CAP_NET_RAW for DNS/network operations)
- Uses separate child profiles for DNS listener, web server, and OpenCanary processes
- Prevents unauthorized access to the host system in case of malicious API calls or misconfigurations

