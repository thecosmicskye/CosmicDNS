#!/usr/bin/env python3

import argparse
import ipaddress
import math
import random
import time
import re
import sys
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import median, quantiles
from urllib.parse import urlparse

# Attempt to import the DNS library
try:
    import dns.message
    import dns.query
    import dns.resolver
    import dns.exception
    import dns.rdatatype
except ImportError:
    print("Error: The 'dnspython' library is required.")
    print("Please install it using: pip install dnspython")
    sys.exit(1)

DEFAULT_UNFILTERED_DOMAINS = [
    "doubleclick.net",
    "pubmatic.com",
    "adservice.google.com",
    "playboy.com",
    "pornhub.com",
    "bet365.com",
    "facebook.com",
    "tiktok.com",
]

DEFAULT_BENCHMARK_DOMAINS = [
    "google.com",
    "youtube.com",
    "cloudflare.com",
    "openai.com",
    "example.com",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "reddit.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "tiktok.com",
    "x.com",
    "yahoo.com",
    "bing.com",
    "cnn.com",
    "bbc.com",
    "nytimes.com",
    "weather.com",
    "github.com",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "vercel.com",
    "discord.com",
    "slack.com",
    "zoom.us",
    "spotify.com",
    "twitch.tv",
    "paypal.com",
    "stripe.com",
    "chase.com",
    "nyc.gov",
    "verizon.com",
    "spectrum.com",
    "att.com",
    "fastly.com",
    "akamai.com",
    "adobe.com",
    "mozilla.org",
    "linkedin.com",
    "pinterest.com",
    "dropbox.com",
    "salesforce.com",
    "shopify.com",
    "walmart.com",
    "doubleclick.net",
    "pubmatic.com",
    "adservice.google.com",
    "playboy.com",
    "pornhub.com",
    "bet365.com",
    "onlyfans.com",
    "roblox.com",
    "steamcommunity.com",
    "epicgames.com",
    "nvidia.com",
    "amd.com",
    "intel.com",
    "duckduckgo.com",
]

DEFAULT_UNCACHED_BENCHMARK_DOMAINS = [
    "local.gd",
    "localhost.direct",
    "lvh.me",
    "localtest.me",
    "vcap.me",
    "1-1-1-1.sslip.io",
    "8-8-8-8.sslip.io",
    "1-1-1-1.nip.io",
    "8-8-8-8.nip.io",
]

def response_a_records(response):
    answers = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            answers.extend(item.to_text() for item in rrset)
    return answers

def doh_query(query, server, timeout):
    last_error = None
    for http_version in (dns.query.HTTPVersion.HTTP_2, dns.query.HTTPVersion.HTTP_1):
        try:
            return dns.query.https(
                query,
                server["url"],
                timeout=timeout,
                port=server["port"],
                path=server["path"],
                bootstrap_address=server.get("bootstrap"),
                http_version=http_version,
            )
        except Exception as exc:
            last_error = exc
    raise last_error

def resolve_a_record(server, query_domain, timeout):
    query = dns.message.make_query(query_domain, "A")

    start_time = time.monotonic()
    protocol = server["protocol"]

    if protocol == "udp":
        response = dns.query.udp(query, server["host"], timeout=timeout, port=server["port"])
    elif protocol == "tcp":
        response = dns.query.tcp(query, server["host"], timeout=timeout, port=server["port"])
    elif protocol == "dot":
        response = dns.query.tls(
            query,
            server.get("bootstrap") or server["host"],
            timeout=timeout,
            port=server["port"],
            server_hostname=server.get("server_hostname") or server["host"],
        )
    elif protocol == "doh":
        response = doh_query(query, server, timeout)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    end_time = time.monotonic()

    return response, end_time - start_time

def test_positive_dns_query(server, query_domain, timeout):
    try:
        response, elapsed = resolve_a_record(server, query_domain, timeout)

        # Check if the query returned a response and the RCODE indicates success (NOERROR)
        if response and response.rcode() == dns.rcode.NOERROR:
             # Ensure we actually got answers in the response
            if response_a_records(response):
                 # print(f"  Success: {ip_address} responded in {elapsed:.3f}s with NOERROR")
                return True, f"Responsive ({elapsed:.3f}s)"
            else:
                # Responded with NOERROR but no actual A records (unlikely for google.com A query but possible)
                return False, "NOERROR/no A records"

        rcode = dns.rcode.to_text(response.rcode()) if response else "no response"
        return False, f"RCODE {rcode}"
    except dns.exception.Timeout:
        return False, f"Timeout > {timeout}s"
    except Exception as e:
        return False, f"Error ({e})"

def test_nxdomain_behavior(server, nxdomain_domain, timeout):
    try:
        response, elapsed = resolve_a_record(server, nxdomain_domain, timeout)
        rcode = dns.rcode.to_text(response.rcode()) if response else "no response"
        answers = response_a_records(response) if response else []

        if rcode == "NXDOMAIN":
            return True, f"NXDOMAIN OK ({elapsed:.3f}s)"
        if answers:
            return False, f"NXDOMAIN hijack: {rcode} with answers {', '.join(answers[:3])}"
        return False, f"NXDOMAIN check failed: {rcode}"
    except dns.exception.Timeout:
        return False, f"NXDOMAIN timeout > {timeout}s"
    except Exception as e:
        return False, f"NXDOMAIN error ({e})"

def is_blocked_address(answer):
    try:
        address = ipaddress.ip_address(answer)
    except ValueError:
        return False

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )

def test_unfiltered_behavior(server, domains, timeout):
    checked_domains = []

    for domain in domains:
        try:
            response, elapsed = resolve_a_record(server, domain, timeout)
            rcode = dns.rcode.to_text(response.rcode()) if response else "no response"
            answers = response_a_records(response) if response else []

            if rcode != "NOERROR":
                return False, f"Filtered check failed for {domain}: {rcode}"
            if not answers:
                return False, f"Filtered check failed for {domain}: no A records"
            if all(is_blocked_address(answer) for answer in answers):
                return False, f"Filtered check failed for {domain}: blocked/null answers {', '.join(answers[:3])}"

            checked_domains.append(f"{domain} ({elapsed:.3f}s)")
        except dns.exception.Timeout:
            return False, f"Filtered check timeout for {domain} > {timeout}s"
        except Exception as e:
            return False, f"Filtered check error for {domain} ({e})"

    return True, f"Unfiltered OK: {', '.join(checked_domains)}"

def is_filter_reason(reason):
    return reason.startswith("Filtered check failed")

def test_dns_server(
    server,
    query_domain,
    timeout,
    require_nxdomain=False,
    nxdomain_domain=None,
    require_unfiltered=False,
    unfiltered_domains=None,
):
    """
    Tests a single DNS server by sending a query.

    Args:
        server (dict): Parsed DNS server endpoint.
        query_domain (str): The domain name to query (e.g., 'google.com').
        timeout (float): The timeout in seconds for the query.
        require_nxdomain (bool): If true, reject servers that do not return
            NXDOMAIN for a nonexistent name.
        nxdomain_domain (str): The nonexistent name to query.
        require_unfiltered (bool): If true, reject servers that block known
            real domains that should resolve on an unfiltered resolver.
        unfiltered_domains (list[str]): Real domains to use for the unfiltered
            check.

    Returns:
        tuple[bool, str, str]: (success, reason, category).
    """
    ok, reason = test_positive_dns_query(server, query_domain, timeout)
    if not ok:
        return False, reason, "failed"

    if require_nxdomain:
        nxdomain_ok, nxdomain_reason = test_nxdomain_behavior(server, nxdomain_domain, timeout)
        if not nxdomain_ok:
            return False, nxdomain_reason, "failed"
        reason = f"{reason}; {nxdomain_reason}"

    if require_unfiltered:
        unfiltered_ok, unfiltered_reason = test_unfiltered_behavior(server, unfiltered_domains, timeout)
        if not unfiltered_ok:
            category = "filtered" if is_filter_reason(unfiltered_reason) else "failed"
            return False, unfiltered_reason, category
        reason = f"{reason}; {unfiltered_reason}"

    return True, reason, "passed"

def split_domains(values):
    domains = []
    for value in values:
        domains.extend(part.strip() for part in value.split(",") if part.strip())
    return domains

def parse_ip_from_line(line):
    """
    Extracts the IP address from the start of a line.
    Handles both IPv4 and IPv6.
    """
    # Regex to find an IPv4 or IPv6 address at the beginning of the string,
    # followed by whitespace.
    # IPv6 part handles various valid formats including compressed ones.
    match = re.match(r'^([0-9a-fA-F:.]+)(?:\s+|$)', line)
    if match:
        ip = match.group(1)
        # Basic validation if it looks like an IP
        if '.' in ip or ':' in ip:
            return ip
    return None

def strip_ranked_prefix(line):
    match = re.match(r'^\d+\.\s+(.+?)(?:\s+#.*)?$', line)
    if match:
        return match.group(1).strip()
    return line

def parse_options(tokens):
    options = {}
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            options[key.strip().lower()] = value.strip()
    return options

def parse_port(parsed, default):
    return parsed.port if parsed.port is not None else default

def parse_dns_server_from_line(line):
    """
    Parses either a legacy UDP line starting with an IP address or an explicit
    protocol URI:

      1.1.1.1 Cloudflare
      udp://1.1.1.1 Cloudflare
      tcp://1.1.1.1 Cloudflare TCP
      doh://dns.example/dns-query bootstrap=1.2.3.4 Example DoH
      dot://dns.example bootstrap=1.2.3.4 Example DoT
    """
    line = strip_ranked_prefix(line)
    tokens = line.split()
    if not tokens:
        return None

    first = tokens[0]
    options = parse_options(tokens[1:])

    if "://" not in first:
        ip = parse_ip_from_line(line)
        if not ip:
            return None
        return {
            "protocol": "udp",
            "host": ip,
            "port": 53,
            "label": ip,
        }

    parsed = urlparse(first)
    protocol = parsed.scheme.lower()

    if protocol == "https":
        protocol = "doh"

    if protocol not in {"udp", "tcp", "dot", "doh"}:
        return None

    host = parsed.hostname
    if not host:
        return None

    if protocol in {"udp", "tcp"}:
        default_port = 53
        label = f"{protocol}://{host}"
    elif protocol == "dot":
        default_port = 853
        label = f"dot://{host}"
    else:
        default_port = 443
        path = parsed.path or "/dns-query"
        label = f"doh://{host}{path}"

    server = {
        "protocol": protocol,
        "host": host,
        "port": parse_port(parsed, default_port),
        "label": label,
    }

    if protocol == "doh":
        server["path"] = parsed.path or "/dns-query"
        server["url"] = first if parsed.scheme.lower() == "https" else f"https://{host}{server['path']}"

    if "bootstrap" in options:
        server["bootstrap"] = options["bootstrap"]
    if "hostname" in options:
        server["server_hostname"] = options["hostname"]

    return server

def read_dns_servers(input_file):
    servers = []
    try:
        with open(input_file, 'r') as f_in:
            for i, line in enumerate(f_in):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('['):
                    continue

                endpoint_line = strip_ranked_prefix(line)
                server = parse_dns_server_from_line(endpoint_line)
                if server:
                    server['original_line'] = endpoint_line
                    servers.append(server)
                else:
                    print(f"Warning: Could not parse DNS endpoint from line {i+1}: '{line}' - Skipping.")
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    return servers

def unique_domains(domains):
    seen = set()
    output = []
    for domain in domains:
        if domain not in seen:
            output.append(domain)
            seen.add(domain)
    return output

def read_domains_file(path):
    domains = []
    try:
        with open(path, 'r') as f_in:
            for line in f_in:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except FileNotFoundError:
        print(f"Error: Domains file not found: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading domains file: {e}")
        sys.exit(1)
    return domains

def cache_busted_domain(base_domain, round_number, server_index, rng):
    base_domain = base_domain.strip().rstrip(".")
    token = f"cosmicdns-{round_number}-{server_index + 1}-{rng.getrandbits(64):016x}"
    return f"{token}.{base_domain}"

def percentile_90(values):
    if not values:
        return float('inf')
    return quantiles(values, n=10)[8] if len(values) >= 10 else max(values)

def sign_test_p_value(wins, total):
    if total == 0:
        return 1.0
    z_score = (wins - total / 2 - 0.5) / math.sqrt(total / 4)
    return 0.5 * math.erfc(z_score / math.sqrt(2))

def query_success_latency(server, domain, timeout):
    response, elapsed = resolve_a_record(server, domain, timeout)
    rcode = dns.rcode.to_text(response.rcode()) if response else "NO_RESPONSE"
    answers = response_a_records(response) if response else []
    if rcode == "NOERROR" and answers:
        return elapsed * 1000, None
    return None, f"{domain}:{rcode}"

def stat_benchmark_rows(servers, samples, failures, nxdomain_ok, nxdomain_total, total_expected):
    rows = []
    for idx, server in enumerate(servers):
        latencies = list(samples[idx].values())
        rows.append({
            "idx": idx,
            "server": server,
            "count": len(latencies),
            "total_expected": total_expected,
            "median": median(latencies) if latencies else float('inf'),
            "p90": percentile_90(latencies),
            "min": min(latencies) if latencies else float('inf'),
            "max": max(latencies) if latencies else float('inf'),
            "failures": len(failures[idx]),
            "nxdomain_ok": nxdomain_ok[idx],
            "nxdomain_total": nxdomain_total[idx],
        })
    rows.sort(key=lambda row: (
        row["failures"],
        row["median"],
        row["p90"],
        row["server"]["original_line"],
    ))
    return rows

def compare_leader(rows, samples, alpha, min_median_diff_ms):
    leader = rows[0]
    leader_samples = samples[leader["idx"]]
    comparisons = []
    ambiguous = []

    for row in rows[1:]:
        common_keys = sorted(set(leader_samples).intersection(samples[row["idx"]]))
        diffs = [samples[row["idx"]][key] - leader_samples[key] for key in common_keys]
        if not diffs:
            comparison = (row, 0, 1.0, 0.0, False)
            comparisons.append(comparison)
            ambiguous.append(comparison)
            continue

        wins = sum(1 for diff in diffs if diff > 0)
        p_value = sign_test_p_value(wins, len(diffs))
        median_diff = median(diffs)
        significant = p_value < alpha and median_diff > min_median_diff_ms
        comparison = (row, len(diffs), p_value, median_diff, significant)
        comparisons.append(comparison)
        if not significant:
            ambiguous.append(comparison)

    return leader, comparisons, ambiguous

def write_stat_benchmark_output(
    output_file,
    input_file,
    servers,
    rows,
    comparisons,
    ambiguous,
    domains,
    round_seconds,
    args,
    seed,
    stop_reason,
):
    leader = rows[0]
    try:
        with open(output_file, 'w') as f_out:
            f_out.write("# CosmicDNS sequential paired statistical benchmark\n")
            f_out.write(f"# input={input_file}\n")
            f_out.write(f"# seed={seed}\n")
            f_out.write(f"# mode=one_dns_query_at_a_time randomized_paired_rounds\n")
            f_out.write(f"# uncached={str(args.uncached).lower()}\n")
            f_out.write(f"# servers={len(servers)} domains={len(domains)} rounds={len(round_seconds)} timeout={args.timeout}s\n")
            f_out.write(f"# alpha={args.alpha} min_median_diff_ms={args.min_median_diff_ms}\n")
            f_out.write(f"# stop_reason={stop_reason}\n")
            f_out.write(f"# leader={leader['server']['original_line']}\n")
            f_out.write(f"# ambiguous_vs_leader={len(ambiguous)}\n")
            f_out.write(f"# round_seconds={', '.join(f'{seconds:.1f}' for seconds in round_seconds)}\n\n")

            f_out.write("[ranked]\n")
            for rank, row in enumerate(rows, 1):
                f_out.write(
                    f"{rank:03d}. {row['server']['original_line']} "
                    f"# median={row['median']:.2f}ms p90={row['p90']:.2f}ms "
                    f"min={row['min']:.2f}ms max={row['max']:.2f}ms "
                    f"samples={row['count']}/{row['total_expected']} "
                    f"nxdomain={row['nxdomain_ok']}/{row['nxdomain_total']} "
                    f"failures={row['failures']}\n"
                )

            f_out.write("\n[leader_pairwise]\n")
            for row, sample_count, p_value, median_diff, significant in comparisons:
                f_out.write(
                    f"{row['server']['original_line']} "
                    f"# paired_n={sample_count} median_slower_than_leader={median_diff:.2f}ms "
                    f"sign_p={p_value:.6g} significant={str(significant).lower()}\n"
                )

            if ambiguous:
                f_out.write("\n[not_significantly_slower_than_leader]\n")
                for row, sample_count, p_value, median_diff, _ in ambiguous:
                    f_out.write(
                        f"{row['server']['original_line']} "
                        f"# paired_n={sample_count} median_slower_than_leader={median_diff:.2f}ms "
                        f"sign_p={p_value:.6g}\n"
                    )

            f_out.write("\n[domains]\n")
            for domain in domains:
                f_out.write(domain + "\n")
    except Exception as e:
        print(f"Error writing benchmark output file: {e}")
        sys.exit(1)

def run_statistical_benchmark(args, servers):
    if args.top and args.top > 0:
        servers = servers[:args.top]
    if not servers:
        print("No valid servers found for statistical benchmark.")
        sys.exit(0)

    domains = DEFAULT_UNCACHED_BENCHMARK_DOMAINS[:] if args.uncached else DEFAULT_BENCHMARK_DOMAINS[:]
    if args.domains_file:
        domains.extend(read_domains_file(args.domains_file))
    domains.extend(split_domains(args.benchmark_domain))
    if args.uncached:
        domains.extend(split_domains(args.uncached_domain))
    domains = unique_domains(domains)

    seed = args.seed if args.seed is not None else int(time.time())
    rng = random.Random(seed)
    samples = {idx: {} for idx in range(len(servers))}
    failures = defaultdict(list)
    nxdomain_ok = defaultdict(int)
    nxdomain_total = defaultdict(int)
    round_seconds = []
    stop_reason = None

    print(f"Input file: {args.input_file}")
    print(f"Output file: {args.output_file}")
    print(f"Statistical benchmark: enabled")
    print(f"Servers: {len(servers)}")
    print(f"Domains: {len(domains)}")
    print(f"Timeout: {args.timeout}s")
    print(f"Rounds: min {args.min_rounds}, max {args.max_rounds}")
    print(f"Seed: {seed}")
    print("Mode: one DNS query at a time, randomized paired rounds")
    if args.uncached:
        print("Cache busting: enabled with randomized wildcard names")

    for round_number in range(1, args.max_rounds + 1):
        started = time.monotonic()
        domain_order = domains[:]
        rng.shuffle(domain_order)

        for domain in domain_order:
            server_order = list(range(len(servers)))
            rng.shuffle(server_order)
            sample_key = (round_number, domain)
            for idx in server_order:
                query_domain = cache_busted_domain(domain, round_number, idx, rng) if args.uncached else domain
                try:
                    latency, failure = query_success_latency(servers[idx], query_domain, args.timeout)
                    if failure:
                        failures[idx].append(failure)
                    else:
                        samples[idx][sample_key] = latency
                except Exception as exc:
                    failures[idx].append(f"{query_domain}:{type(exc).__name__}:{exc}")

        server_order = list(range(len(servers)))
        rng.shuffle(server_order)
        for idx in server_order:
            domain = f"cosmicdns-stat-{round_number}-{uuid.uuid4().hex}.invalid."
            nxdomain_total[idx] += 1
            try:
                response, _ = resolve_a_record(servers[idx], domain, args.timeout)
                rcode = dns.rcode.to_text(response.rcode()) if response else "NO_RESPONSE"
                if rcode == "NXDOMAIN":
                    nxdomain_ok[idx] += 1
                else:
                    failures[idx].append(f"{domain}:{rcode}")
            except Exception as exc:
                failures[idx].append(f"{domain}:{type(exc).__name__}:{exc}")

        elapsed = time.monotonic() - started
        round_seconds.append(elapsed)
        total_expected = len(round_seconds) * len(domains)
        rows = stat_benchmark_rows(servers, samples, failures, nxdomain_ok, nxdomain_total, total_expected)
        leader, comparisons, ambiguous = compare_leader(rows, samples, args.alpha, args.min_median_diff_ms)

        print(
            f"Round {round_number}/{args.max_rounds}: {elapsed:.1f}s, "
            f"leader {leader['median']:.2f}ms ({leader['server']['original_line']}), "
            f"not significant vs leader: {len(ambiguous)}"
        )
        print("  Top 5: " + " | ".join(
            f"{row['median']:.2f}ms {row['server']['original_line'][:42]}" for row in rows[:5]
        ))

        if round_number >= args.min_rounds and not ambiguous:
            stop_reason = f"leader_significant_after_{round_number}_rounds"
            break

    if stop_reason is None:
        rows = stat_benchmark_rows(
            servers,
            samples,
            failures,
            nxdomain_ok,
            nxdomain_total,
            len(round_seconds) * len(domains),
        )
        leader, comparisons, ambiguous = compare_leader(rows, samples, args.alpha, args.min_median_diff_ms)
        stop_reason = f"max_rounds_reached_{args.max_rounds}_ambiguous_{len(ambiguous)}"

    write_stat_benchmark_output(
        args.output_file,
        args.input_file,
        servers,
        rows,
        comparisons,
        ambiguous,
        domains,
        round_seconds,
        args,
        seed,
        stop_reason,
    )

    print(f"\nStatistical benchmark complete: {stop_reason}")
    print(f"Results saved to: {args.output_file}")
    print("Final top 10:")
    for rank, row in enumerate(rows[:10], 1):
        print(
            f"{rank:02d}. {row['median']:.2f}ms p90={row['p90']:.2f}ms "
            f"samples={row['count']}/{row['total_expected']} "
            f"nxdomain={row['nxdomain_ok']}/{row['nxdomain_total']} "
            f"failures={row['failures']} {row['server']['original_line']}"
        )

def write_filter_output(output_file, passed_servers, filtered_servers, failed_servers, classified):
    try:
        with open(output_file, 'w') as f_out:
            if not classified:
                for line, _ in passed_servers:
                    f_out.write(line + '\n')
                return

            f_out.write("[passed]\n")
            for line, reason in passed_servers:
                f_out.write(f"{line} # {reason}\n")

            f_out.write("\n[filtered]\n")
            for line, reason in filtered_servers:
                f_out.write(f"{line} # {reason}\n")

            f_out.write("\n[failed]\n")
            for line, reason in failed_servers:
                f_out.write(f"{line} # {reason}\n")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Filter a list of DNS servers based on responsiveness.")
    parser.add_argument("input_file", help="Path to the input file (e.g., dns_servers.ini) containing DNS endpoints.")
    parser.add_argument("output_file", help="Path to the output file where responsive servers will be saved.")
    parser.add_argument("-d", "--domain", default="google.com", help="Domain to query for testing (default: google.com).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout in seconds for each DNS query (default: 1.0).")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of parallel workers for testing (default: 10).")
    parser.add_argument("--require-nxdomain", action="store_true", help="Reject DNS servers that do not return NXDOMAIN for a nonexistent domain.")
    parser.add_argument("--nxdomain-domain", help="Nonexistent domain for the NXDOMAIN check. Defaults to a random .invalid name.")
    parser.add_argument("--require-unfiltered", action="store_true", help="Reject DNS servers that appear to block/null-route known real domains.")
    parser.add_argument(
        "--unfiltered-domain",
        action="append",
        default=[],
        help="Real domain to use for filtration checks. May be repeated or comma-separated. Defaults to common ad/content domains.",
    )
    parser.add_argument("--stat-benchmark", action="store_true", help="Run a sequential paired statistical benchmark instead of the parallel responsiveness filter.")
    parser.add_argument("--top", type=int, default=0, help="Limit statistical benchmark to the first N parsed endpoints (use with ranked output files for top-N runs).")
    parser.add_argument("--min-rounds", type=int, default=6, help="Minimum paired benchmark rounds before significance stopping is allowed (default: 6).")
    parser.add_argument("--max-rounds", type=int, default=12, help="Maximum paired benchmark rounds (default: 12).")
    parser.add_argument("--alpha", type=float, default=0.05, help="One-sided sign-test alpha for leader separation (default: 0.05).")
    parser.add_argument("--min-median-diff-ms", type=float, default=0.3, help="Minimum paired median latency gap required for significance (default: 0.3ms).")
    parser.add_argument("--seed", type=int, help="Random seed for reproducible benchmark order.")
    parser.add_argument("--domains-file", help="Optional file containing additional benchmark domains, one per line.")
    parser.add_argument(
        "--benchmark-domain",
        action="append",
        default=[],
        help="Additional statistical benchmark domain. May be repeated or comma-separated.",
    )
    parser.add_argument(
        "--uncached",
        action="store_true",
        help="In statistical benchmark mode, generate fresh wildcard names so resolver caches are bypassed.",
    )
    parser.add_argument(
        "--uncached-domain",
        action="append",
        default=[],
        help="Wildcard base domain for --uncached benchmark. May be repeated or comma-separated.",
    )

    args = parser.parse_args()
    nxdomain_domain = args.nxdomain_domain or f"cosmicdns-{uuid.uuid4().hex}.invalid."
    unfiltered_domains = split_domains(args.unfiltered_domain) or DEFAULT_UNFILTERED_DOMAINS

    servers_to_test = read_dns_servers(args.input_file)
    if args.stat_benchmark:
        run_statistical_benchmark(args, servers_to_test)
        return

    print(f"Input file: {args.input_file}")
    print(f"Output file: {args.output_file}")
    print(f"Query domain: {args.domain}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")
    if args.require_nxdomain:
        print(f"NXDOMAIN check: enabled ({nxdomain_domain})")
    if args.require_unfiltered:
        print(f"Unfiltered check: enabled ({', '.join(unfiltered_domains)})")

    if not servers_to_test:
        print("No valid servers found in the input file.")
        sys.exit(0)

    print(f"\nFound {len(servers_to_test)} servers to test. Starting checks...")

    responsive_servers = []
    filtered_servers = []
    failed_servers = []
    tested_count = 0
    total_servers = len(servers_to_test)

    # Use ThreadPoolExecutor for parallel testing
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Create future tasks
        future_to_server = {
            executor.submit(
                test_dns_server,
                server,
                args.domain,
                args.timeout,
                args.require_nxdomain,
                nxdomain_domain,
                args.require_unfiltered,
                unfiltered_domains,
            ): server
            for server in servers_to_test
        }

        for future in as_completed(future_to_server):
            server_info = future_to_server[future]
            label = server_info['label']
            original_line = server_info['original_line']
            tested_count += 1
            try:
                is_responsive, reason, category = future.result()
                if is_responsive:
                    responsive_servers.append((original_line, reason))
                    status = reason
                elif category == "filtered":
                    filtered_servers.append((original_line, reason))
                    status = reason
                else:
                    failed_servers.append((original_line, reason))
                    status = reason
            except Exception as exc:
                print(f"Error testing {label}: {exc}")
                failed_servers.append((original_line, f"Error ({exc})"))
                status = f"Error ({exc})"

            # Print progress
            print(f"\rProgress: {tested_count}/{total_servers} tested ({status} for {label})...", end="")

    print("\n\nTesting complete.") # Newline after progress indicator

    # Sort the responsive servers based on the original line order (or IP if needed)
    # Sorting might be complex if original order isn't preserved perfectly by threading.
    # For simplicity, we'll sort the final list alphabetically by the original line.
    responsive_servers.sort()
    filtered_servers.sort()
    failed_servers.sort()

    print(f"Found {len(responsive_servers)} responsive servers.")
    if args.require_unfiltered:
        print(f"Found {len(filtered_servers)} filtered servers.")
        print(f"Found {len(failed_servers)} failed servers.")

    write_filter_output(
        args.output_file,
        responsive_servers,
        filtered_servers,
        failed_servers,
        args.require_unfiltered,
    )
    print(f"Results saved to: {args.output_file}")

if __name__ == "__main__":
    main()
