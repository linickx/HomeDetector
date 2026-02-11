# Agent Instructions for HomeDetector
<!-- Created by Copilot using model Claude Haiku 4.5 on 2026-02-01 -->
<!-- Modified by Copilot using model GPT-5 mini on 2026-02-04 -->
<!-- Modified by GitHub Copilot CLI on 2026-02-06 -->

This document provides guidance for AI agents on how to understand, modify, and contribute to the HomeDetector project.

## Project Overview

HomeDetector is a lightweight network intrusion detection system (IDS) and honeypot, primarily designed for Home Assistant users. Its main purpose is to monitor local network traffic, with a focus on IoT devices, and detect anomalous behavior. For more details on the platform, see the [Home Assistant developer documentation](https://developers.home-assistant.io/docs/apps).

There are two core features:
1.  **DNS Anomaly Detection**: A custom DNS listener intercepts queries from configured network scopes (e.g., your IoT VLAN). It learns which domains devices normally access and can alert on or block queries to new, unrecognized domains.
2.  **Honeypot**: It uses a pre-configured OpenCanary instance to emulate services like Telnet and FTP. Any attempted interaction with these honeypot services triggers an alert.

Alerts from both components are sent to a central admin panel and can be forwarded to Home Assistant as notifications.

## Architecture

The system is composed of three main Python-based components that run concurrently:

1.  **DNS Listener (`dns/listener.py`)**:
    *   A custom DNS server built with `dnslib`.
    *   It listens on port 10053 (mapped to 53 in the container).
    *   It maintains a SQLite database (`/config/hd.db`) to store information about network scopes, known devices, requested domains, and specific queries.
    *   When an anomaly is detected (based on its learning/blocking rules), it sends a JSON payload via an HTTP POST request to the admin web server's `/notify` endpoint.

2.  **Admin Web Server (`admin/web.py`)**:
    *   A web application built using the `twisted` library for the server and `jinja2` for HTML templating.
    *   It serves the main administrative UI for viewing alerts and configuring detection rules.
    *   It exposes a `/notify` webhook endpoint that receives alerts from the DNS Listener and OpenCanary.
    *   It stores received alerts in the same SQLite database (`hd.db`).
    *   It can integrate with Home Assistant to push notifications.

3.  **OpenCanary (`opencanary/`)**:
    *   A standard OpenCanary honeypot. For more details, refer to the [official OpenCanary documentation](https://docs.opencanary.org/en/latest/).
    *   Its configuration (`opencanary.conf`) is set up to use the `webhook` logger, which POSTs alerts in JSON format to the admin server's `/notify` endpoint.

## Key Technologies

*   **Backend**: Python 3
*   **Core Components**:
    *   DNS Server: `dnslib`, `netaddr`
    *   Web Server: `twisted`
    *   Web Templating: `jinja2`
    *   Database: `sqlite3` (built-in)
*   **Frontend**:
    *   Framework: Bootstrap
    *   JavaScript Libraries: jQuery, `bootstrap-table`, `bootstrap-editable`
*   **Deployment**: Docker

## Development Workflow

### Virtual Environment
<!-- Modified by Gemini using model gemini-1.5-pro-001 on 2026-02-05 -->
This project uses `uv` to manage the Python virtual environment. All `python` and `pip` commands MUST be executed using the project's virtual environment located in the `.venv` directory. This ensures consistency and avoids conflicts with system-wide packages.

For example, use `.venv/bin/python` and `.venv/bin/pip`.

### Setup

1.  The application is designed to run in a Home Assistant environment or a Docker container.
2.  Dependencies for each component are listed in `requirements.txt` files within their respective directories (`admin/`, `dns/`, `opencanary/`). To set up a local development environment, you must create a Python virtual environment using `uv` and install these dependencies into it.

    ```bash
    uv venv
    uv pip install -r admin/requirements.txt -r dns/requirements.txt -r opencanary/requirements.txt
    ```
3.  The central database is `hd.db`, located in the `/config/` directory in the container, or the project root during local development.

### Running the Application

The `run.sh` script is the main entry point. It launches the three key processes:
1.  OpenCanary (`opencanaryd`)
2.  DNS Listener (`dns/listener.py`)
3.  Admin Web Server (`admin/web.py`)

### Making Changes

*   **Backend (Python)**:
    *   Before making changes, identify which component is responsible for the desired functionality (DNS, Admin, or Honeypot).
    *   **DNS Logic**: All DNS interception, learning, and detection logic is in `dns/listener.py`.
    *   **Admin UI/API**: The web pages, API endpoints for the UI tables, and alert handling logic are in `admin/web.py`. The HTML structure is in the `admin/templates/*.j2` files.
    *   Follow existing Python code style. The code uses standard library features extensively and defines classes for different web pages and backend tasks.

*   **Frontend (HTML/JS)**:
    *   The frontend is built with Jinja2 templates located in `admin/templates/`.
    *   The main pages are `admin.j2` (Alerts), `dns.j2` (DNS logs), and `tuning.j2` (Network/Host configuration).
    *   JavaScript functionality relies heavily on jQuery and the `bootstrap-table` plugin, which fetches data from the JSON API endpoints defined in `admin/web.py` (e.g., `/admin/data/alerts`). To modify frontend behavior, you will likely need to interact with the `bootstrap-table` JavaScript API.

### Testing
<!-- Modified by Gemini using model gemini-1.5-pro-001 on 2026-02-05 -->
The project uses `pytest` for unit and integration testing, and `tox` to automate the process. Tests are located in the `tests/` directory, with subdirectories for each component (`admin`, `dns`).

*   **Admin Tests (`tests/admin/`)**: These tests cover the `admin/web.py` component. They use `pytest-twisted` to handle the asynchronous nature of the `twisted` web server.
*   **DNS Tests (`tests/dns/`)**: These tests cover the `dns/listener.py` component.

Each test directory contains its own `requirements.txt` to specify its Python dependencies.

To run all tests and generate coverage reports, simply run `tox` from the project root:
```bash
tox
```

This will create separate virtual environments for each test suite, install the necessary dependencies, and run the tests. Coverage reports will be generated in the `htmlcov/` directory.

You can also run a specific test environment:
```bash
tox -e test-admin
tox -e test-dns
```

If you want to run the tests manually, you can still do so:
```bash
# Example for running admin tests
cd tests/admin
pip install -r requirements.txt
pytest
```

### Building the Docker Image

To build the Docker image locally using podman, use the build script located in the `tests/` directory:

```bash
tests/build.sh
```

This script automatically:
1. Detects the system architecture (x86_64/amd64 or aarch64/arm64)
2. Reads the appropriate base image from `build.yaml` based on your architecture
3. Builds the Docker image with podman using the `homedetector:latest` tag and the correct `BUILD_FROM` argument

The base images are defined in `build.yaml`:
- **amd64**: `ghcr.io/home-assistant/amd64-base:3.22`
- **aarch64**: `ghcr.io/home-assistant/aarch64-base:3.22`

### Database

*   The database schema is defined and initialized in both `dns/listener.py` and `admin/web.py`.
*   `dns/listener.py` creates the tables for `domains`, `queries`, `networks`, and `hosts`.
*   `admin/web.py` creates the table for `alerts` and views for joining the DNS tables.
*   All SQL interactions are performed using the standard `sqlite3` library with parameterized queries to prevent injection.

## AI Attribution (Required for New Work)

Any new file or function created by an AI agent must include an attribution comment in the file header and/or the function docstring. The attribution must name the agent and the model used. If attribution already exists for a given day, do not duplicate.

Required format (use the agent's real name/model):
- "Created by <AgentName> using model <ModelName> on <YYYY-MM-DD>"

If an AI agent modifies existing work, add:
- "Modified by <AgentName> using model <ModelName> on <YYYY-MM-DD>"

Placement guidelines by file type:
- Markdown: place the attribution HTML comment immediately below the main title heading (the top-level `#` line).
- Python: module docstring and/or function docstring.
- CSS/JavaScript: file header comment and/or function comment.
- Shell/YAML (including GitHub Workflows): file header comment as the first line.

Examples:
- "Created by Copilot using model gpt-4o on 2026-01-28"
- "Created by Codex using model gpt-2.5-codex on 2026-01-28"
- "Modified by Copilot using model GPT-5 mini on 2026-02-04"
