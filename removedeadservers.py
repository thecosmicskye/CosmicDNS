#!/usr/bin/env python3

import argparse
import socket
import time
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Attempt to import the DNS library
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("Error: The 'dnspython' library is required.")
    print("Please install it using: pip install dnspython")
    sys.exit(1)

def test_dns_server(ip_address, query_domain, timeout):
    """
    Tests a single DNS server by sending a query.

    Args:
        ip_address (str): The IP address of the DNS server to test.
        query_domain (str): The domain name to query (e.g., 'google.com').
        timeout (float): The timeout in seconds for the query.

    Returns:
        bool: True if the server responds successfully within the timeout, False otherwise.
    """
    resolver = dns.resolver.Resolver(configure=False) # Don't use system resolvers
    resolver.nameservers = [ip_address]
    resolver.timeout = timeout
    resolver.lifetime = timeout # Total time for query attempt

    try:
        # Perform a simple A record query
        start_time = time.monotonic()
        answers = resolver.resolve(query_domain, 'A')
        end_time = time.monotonic()
        # Check if we got at least one answer and it happened within the timeout
        # (redundant check as resolve should raise timeout exception, but good practice)
        if answers and (end_time - start_time) <= timeout:
            # print(f"  Success: {ip_address} responded in {end_time - start_time:.3f}s")
            return True
        else:
            # This case might not be reached if timeout exception is always raised
            # print(f"  Failure: {ip_address} - No answer or internal timeout issue.")
            return False
    except dns.exception.Timeout:
        # print(f"  Failure: {ip_address} - Query timed out (> {timeout}s).")
        return False
    except dns.resolver.NoNameservers as e:
        # This might happen if the IP is invalid or unreachable at a network level
        # print(f"  Failure: {ip_address} - No nameservers error: {e}")
        return False
    except dns.resolver.NoAnswer:
        # Server responded but had no answer for the query domain - counts as responsive
        # print(f"  Success: {ip_address} - Responded but no answer for {query_domain}.")
        return True
    except Exception as e:
        # Catch other potential errors (e.g., network errors, permission issues)
        # print(f"  Failure: {ip_address} - An unexpected error occurred: {e}")
        return False

def parse_ip_from_line(line):
    """
    Extracts the IP address from the start of a line.
    Handles both IPv4 and IPv6.
    """
    # Regex to find an IPv4 or IPv6 address at the beginning of the string,
    # followed by whitespace.
    # IPv6 part handles various valid formats including compressed ones.
    match = re.match(r'^([0-9a-fA-F:.]+)\s+', line)
    if match:
        ip = match.group(1)
        # Basic validation if it looks like an IP
        if '.' in ip or ':' in ip:
            return ip
    return None

def main():
    parser = argparse.ArgumentParser(description="Filter a list of DNS servers based on responsiveness.")
    parser.add_argument("input_file", help="Path to the input file (e.g., dns_servers.ini) containing IP addresses and hostnames.")
    parser.add_argument("output_file", help="Path to the output file where responsive servers will be saved.")
    parser.add_argument("-d", "--domain", default="google.com", help="Domain to query for testing (default: google.com).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout in seconds for each DNS query (default: 1.0).")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of parallel workers for testing (default: 10).")

    args = parser.parse_args()

    print(f"Input file: {args.input_file}")
    print(f"Output file: {args.output_file}")
    print(f"Query domain: {args.domain}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")

    servers_to_test = []
    try:
        with open(args.input_file, 'r') as f_in:
            for i, line in enumerate(f_in):
                line = line.strip()
                if not line or line.startswith('#'): # Skip empty lines and comments
                    continue

                ip = parse_ip_from_line(line)
                if ip:
                    servers_to_test.append({'ip': ip, 'original_line': line})
                else:
                    print(f"Warning: Could not parse IP address from line {i+1}: '{line}' - Skipping.")

    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    if not servers_to_test:
        print("No valid servers found in the input file.")
        sys.exit(0)

    print(f"\nFound {len(servers_to_test)} servers to test. Starting checks...")

    responsive_servers = []
    tested_count = 0
    total_servers = len(servers_to_test)

    # Use ThreadPoolExecutor for parallel testing
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Create future tasks
        future_to_server = {executor.submit(test_dns_server, server['ip'], args.domain, args.timeout): server for server in servers_to_test}

        for future in as_completed(future_to_server):
            server_info = future_to_server[future]
            ip = server_info['ip']
            original_line = server_info['original_line']
            tested_count += 1
            try:
                is_responsive = future.result()
                if is_responsive:
                    responsive_servers.append(original_line)
                    status = "Responsive"
                else:
                    status = "No Response/Timeout"
            except Exception as exc:
                print(f"Error testing {ip}: {exc}")
                status = f"Error ({exc})"

            # Print progress
            print(f"\rProgress: {tested_count}/{total_servers} tested ({status} for {ip})...", end="")

    print("\n\nTesting complete.") # Newline after progress indicator

    # Sort the responsive servers based on the original line order (or IP if needed)
    # Sorting might be complex if original order isn't preserved perfectly by threading.
    # For simplicity, we'll sort the final list alphabetically by the original line.
    responsive_servers.sort()

    print(f"Found {len(responsive_servers)} responsive servers.")

    try:
        with open(args.output_file, 'w') as f_out:
            for line in responsive_servers:
                f_out.write(line + '\n')
        print(f"Responsive servers saved to: {args.output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
