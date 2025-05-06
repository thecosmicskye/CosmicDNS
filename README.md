# CosmicDNS - DNS Server Responsiveness Checker

## Overview

CosmicDNS is a Python script designed to check the responsiveness of a list of DNS servers. It reads a list of server IPs from an input file, performs a DNS query (defaulting to an A record lookup for `google.com`) against each server, and writes the list of responsive servers (those that reply successfully with a `NOERROR` status) to an output file.

This script utilizes multithreading to speed up the checking process.

## Features

*   Reads DNS server IPs from a specified input file.
*   Tests servers by performing a DNS query (configurable domain and record type, though currently hardcoded to 'A').
*   Filters out servers that time out, refuse connection, or return errors other than `NOERROR`.
*   Uses multithreading (`ThreadPoolExecutor`) for faster parallel checking.
*   Outputs the list of strictly responsive servers to a specified file.
*   Handles both IPv4 and IPv6 addresses.
*   Skips commented lines (`#`) and empty lines in the input file.

## Setup

1.  **Clone the repository (if applicable):**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  **Create a Python virtual environment:**
    It's recommended to use a virtual environment to manage dependencies.
    ```bash
    # For Windows
    python -m venv .venv
    .\.venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    Install the required Python packages using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from your terminal using the following command structure:

```bash
python removedeadservers.py <input_file> <output_file> [options]
```

**Arguments:**

*   `input_file`: (Required) Path to the input file containing the list of DNS server IPs (e.g., `dns_servers.ini`). Each line should start with an IP address.
*   `output_file`: (Required) Path where the list of responsive servers will be saved (e.g., `responsive_servers.ini`).

**Options:**

*   `-d DOMAIN`, `--domain DOMAIN`: Domain to query for testing (default: `google.com`).
*   `-t TIMEOUT`, `--timeout TIMEOUT`: Timeout in seconds for each DNS query (default: `1.0`).
*   `-w WORKERS`, `--workers WORKERS`: Number of parallel workers for testing (default: `10`).

**Example:**

```bash
python removedeadservers.py dns_servers.ini responsive_dns_servers.ini -t 0.5 -w 20
```
This command will:
*   Read servers from `dns_servers.ini`.
*   Test them by querying `google.com` with a 0.5-second timeout.
*   Use 20 parallel workers.
*   Save the responsive servers to `responsive_dns_servers.ini`.

## Input File Format (`dns_servers.ini`)

The input file should list DNS servers, one per line. The script expects the IP address to be at the beginning of the line, followed by optional whitespace and other information (which will be preserved in the output file).

```
# This is a comment
1.1.1.1       # Cloudflare Primary
8.8.8.8       Google Public DNS 1
2001:4860:4860::8888 Google Public DNS IPv6 1
# 192.168.1.1  (This would be skipped if uncommented, unless it's a public DNS)
```

## Output File Format (`responsive_dns_servers.ini`)

The output file will contain only the lines from the input file corresponding to the servers that passed the responsiveness check (returned `NOERROR` for the query within the timeout). The original line format is preserved, and the lines are sorted alphabetically.

## `.gitignore`

A `.gitignore` file is included to prevent committing `.ini` files (which might contain large lists) and the Python virtual environment directory (`.venv/`) to the repository.
