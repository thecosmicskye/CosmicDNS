# CosmicDNS - DNS Server Responsiveness Checker

## Overview

CosmicDNS is a Python CLI designed to check and benchmark DNS resolvers. It reads resolver endpoints from an input file, performs DNS queries against each endpoint, and can either write the responsive resolvers or run a sequential paired benchmark for latency ranking.

This script utilizes multithreading to speed up the checking process.

## Features

*   Reads DNS server IPs from a specified input file.
*   Tests servers by performing a DNS query (configurable domain and record type, though currently hardcoded to 'A').
*   Filters out servers that time out, refuse connection, or return errors other than `NOERROR`.
*   Optionally rejects resolvers that hijack nonexistent domains instead of returning `NXDOMAIN`.
*   Optionally rejects resolvers that appear to filter/block known real domains.
*   Supports plain DNS over UDP/TCP plus DNS-over-HTTPS and DNS-over-TLS endpoints.
*   Can run a sequential paired statistical benchmark with one DNS query in flight at a time.
*   Can run cache-busted uncached benchmarks against wildcard DNS zones.
*   Uses multithreading (`ThreadPoolExecutor`) for faster parallel checking.
*   Outputs the list of strictly responsive servers to a specified file.
*   Separates filtered resolvers from dead or broken resolvers when `--require-unfiltered` is enabled.
*   Handles both IPv4 and IPv6 addresses.
*   Skips commented lines (`#`) and empty lines in the input file.

## Setup

1.  **Clone the repository (if applicable):**
    ```bash
    git clone https://github.com/Cosmic-Skye/CosmicDNS
    cd CosmicDNS
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
python cosmicdns.py <input_file> <output_file> [options]
```

**Arguments:**

*   `input_file`: (Required) Path to the input file containing the list of DNS server endpoints (e.g., `dns_servers.ini`). Each line should start with an IP address or a supported endpoint URI.
*   `output_file`: (Required) Path where the list of responsive servers will be saved (e.g., `responsive_servers.ini`).

**Options:**

*   `-d DOMAIN`, `--domain DOMAIN`: Domain to query for testing (default: `google.com`).
*   `-t TIMEOUT`, `--timeout TIMEOUT`: Timeout in seconds for each DNS query (default: `1.0`).
*   `-w WORKERS`, `--workers WORKERS`: Number of parallel workers for testing (default: `10`).
*   `--require-nxdomain`: Reject DNS servers that do not return `NXDOMAIN` for a nonexistent test domain.
*   `--nxdomain-domain DOMAIN`: Nonexistent domain to use for the `NXDOMAIN` check. Defaults to a random `.invalid` name.
*   `--require-unfiltered`: Reject DNS servers that appear to filter or null-route known real domains.
*   `--unfiltered-domain DOMAIN`: Domain to use for filtration checks. May be repeated or comma-separated. Defaults to real domains across ad, adult, gambling, and social categories.
*   `--stat-benchmark`: Run a sequential paired statistical benchmark instead of the parallel responsiveness filter.
*   `--top N`: Benchmark only the first N parsed endpoints. This works with `ranked_dns_servers.ini` output, so `--top 40` benchmarks the current top 40.
*   `--min-rounds N`, `--max-rounds N`: Minimum and maximum paired benchmark rounds.
*   `--alpha VALUE`: One-sided sign-test threshold for declaring the leader statistically separated.
*   `--min-median-diff-ms MS`: Minimum paired median latency gap required before treating a statistically significant gap as practically meaningful.
*   `--domains-file FILE`: Add benchmark domains from a file.
*   `--benchmark-domain DOMAIN`: Add benchmark domains on the command line. May be repeated or comma-separated.
*   `--uncached`: In statistical benchmark mode, generate a fresh random query name for each resolver under wildcard DNS zones so resolver caches are bypassed.
*   `--uncached-domain DOMAIN`: Wildcard base domain for `--uncached` mode. May be repeated or comma-separated.

**Example:**

```bash
python cosmicdns.py dns_servers.ini responsive_dns_servers.ini -t 0.5 -w 20
```
This command will:
*   Read servers from `dns_servers.ini`.
*   Test them by querying `google.com` with a 0.5-second timeout.
*   Use 20 parallel workers.
*   Save the responsive servers to `responsive_dns_servers.ini`.

```bash
python cosmicdns.py dns_servers.ini clean_dns_servers.ini --require-nxdomain --require-unfiltered -t 1.0 -w 20
```
This command also rejects DNS servers that redirect or synthesize answers for nonexistent domains and DNS servers that appear to block known real domains. With `--require-unfiltered`, the output file uses `[passed]`, `[filtered]`, and `[failed]` sections.

```bash
python cosmicdns.py ranked_dns_servers.ini stat_sig_top40_results.ini --stat-benchmark --top 40 -t 2.5 --min-rounds 6 --max-rounds 12
```
This command reads the current ranked list, takes the top 40 endpoints, and runs a paired benchmark with one DNS query in flight at a time. Each round queries the same domain set against every resolver in randomized order, then runs an `NXDOMAIN` check. The output includes rankings, paired comparisons against the leader, and any resolvers that were not significantly slower than the leader.

```bash
python cosmicdns.py ranked_dns_servers.ini stat_sig_top40_uncached_results.ini --stat-benchmark --top 40 --uncached -t 3 --min-rounds 6 --max-rounds 12
```
This command runs the same one-at-a-time benchmark, but uses fresh randomized names under wildcard DNS zones such as `local.gd`, `localhost.direct`, `lvh.me`, `sslip.io`, and `nip.io`. This avoids measuring resolver-side cached answers from prior rounds.

`removedeadservers.py` remains as a backward-compatible wrapper for older commands.

## Input File Format (`dns_servers.ini`)

The input file should list DNS servers, one per line. Plain IP lines are treated as DNS-over-UDP/53. Protocol-aware endpoints can use `udp://`, `tcp://`, `doh://`, `https://`, or `dot://`. Add `bootstrap=<ip>` when a DoH/DoT hostname should be reached through a specific resolver IP.

```
# This is a comment
1.1.1.1       # Cloudflare Primary
8.8.8.8       Google Public DNS 1
2001:4860:4860::8888 Google Public DNS IPv6 1
doh://dns.google/dns-query bootstrap=8.8.8.8 Google Public DNS DoH
dot://dns.mullvad.net bootstrap=194.242.2.2 Mullvad DNS over TLS
# 192.168.1.1  (This would be skipped if uncommented, unless it's a public DNS)
```

## Output File Format (`responsive_dns_servers.ini`)

Without `--require-unfiltered`, the output file contains only the lines from the input file corresponding to the servers that passed the responsiveness check. With `--require-unfiltered`, the output file contains `[passed]`, `[filtered]`, and `[failed]` sections. Filtered resolvers are endpoints that responded but blocked, null-routed, or returned `NXDOMAIN` for a real filtration-check domain; failed resolvers are timeouts, routing errors, malformed responses, or NXDOMAIN-hijacking failures.

## `.gitignore`

A `.gitignore` file is included to prevent committing `.ini` files (which might contain large lists) and the Python virtual environment directory (`.venv/`) to the repository.
