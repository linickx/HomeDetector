# Security

## 📩 Contact

To report a security issue, contact me via my website [linickx.com](https://www.linickx.com) or Mastodon [@linickx@infosec.exchange](https://infosec.exchange/@linickx)

## 🔎 Software Bill of Materials

For transparency of the Docker Image contents, and SBOM is now attached to new releases.

## 🔒 AppArmor

HomeDetector implements a single AppArmor security profile (`apparmor.txt`) to restrict system access and provide defence-in-depth. The profile:

- Restricts file system access to application, configuration, and data directories (e.g. `/app/`, `/config/`, `/data/`)
- Denies key dangerous Linux capabilities (e.g. `sys_admin`, `dac_override`)
- Permits necessary network socket access (inet, unix) for application services
- Confines container processes under a unified `homedetector` profile

## 🍯 Honeypot Credential Logging

HomeDetector intentionally logs captured attacker credentials from honeypot interactions to:

1. **Alert administrators** of active attack attempts on the honeypot services
2. **Provide forensic data** for investigating attacker behavior and tools
3. **Enable integration** with Home Assistant for real-time security notifications

These logged credentials are from simulated/honeypot services (not real accounts) and represent legitimate security telemetry. CodeQL's clear-text logging check may flag this as a false positive—see [`CODEQL_SUPPRESSION.md`](./CODEQL_SUPPRESSION.md) for details on how these findings are suppressed in security scanning.

