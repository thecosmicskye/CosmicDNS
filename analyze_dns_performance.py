import argparse
import csv
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.exception

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Analyze DNS server performance (average response time and reliability).")
    parser.add_argument("input_file", help="Path to the input file containing DNS server IPs.")
    parser.add_argument("output_file", help="Path to the output CSV file for results.")
    parser.add_argument("-n", "--num_requests", type=int, default=10, help="Number of queries to send to each server (default: 10).")
    parser.add_argument("-d", "--domain", default="google.com", help="Domain to query for testing (default: google.com).")
    parser.add_argument("-r", "--record_type", default="A", help="Record type to query (default: A).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout in seconds for each DNS query (default: 1.0).")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of parallel workers for testing (default: 10).")
    return parser.parse_args()

def read_servers(input_file):
    """
    Reads server IPs and their original lines from the input file,
    skipping comments and empty lines. Returns a dictionary mapping IP to the full line.
    """
    servers_map = {}
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    parts = stripped_line.split(maxsplit=1)
                    server_ip = parts[0]
                    # Store the full original stripped line associated with the IP
                    servers_map[server_ip] = stripped_line
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        exit(1)
    except Exception as e:
        print(f"Error reading input file {input_file}: {e}")
        exit(1)
    if not servers_map:
        print(f"Error: No valid server IPs found in {input_file}")
        exit(1)
    print(f"Read {len(servers_map)} server entries from {input_file}")
    return servers_map

def query_server(server_ip, domain, record_type, timeout):
    """Performs a single DNS query and returns response time or None on failure."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server_ip]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    start_time = time.monotonic()
    try:
        resolver.resolve(domain, record_type, raise_on_no_answer=False) # raise_on_no_answer=False to treat NOERROR with no answers as success
        end_time = time.monotonic()
        # Check the response code if needed, but for timing, success is reaching here without exception
        # We consider any successful resolution (even NXDOMAIN or NOERROR with no answers) as a valid response for performance timing.
        # Timeout, Refused, ServFail etc. will raise exceptions.
        return (end_time - start_time) * 1000 # Return time in milliseconds
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException) as e:
        # print(f"Query failed for {server_ip}: {e}") # Optional: for debugging
        return None # Indicate failure

def analyze_servers(servers_map, num_requests, domain, record_type, timeout, max_workers):
    """
    Analyzes servers by sending multiple queries and calculating stats.
    Takes a dictionary mapping server IP to the original line.
    """
    server_ips = list(servers_map.keys())
    server_stats = {ip: {'times': [], 'success_count': 0, 'total_sent': 0} for ip in server_ips}
    # Create a list of tasks (server IPs) to query, duplicating for num_requests
    tasks_to_submit = server_ips * num_requests

    print(f"Starting analysis: {len(server_ips)} servers, {num_requests} requests each, {max_workers} workers...")

    # Shuffle the task list to better distribute queries across servers over time
    import random
    random.shuffle(tasks_to_submit)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map futures back to the server IP they are testing
        future_to_server_ip = {executor.submit(query_server, ip, domain, record_type, timeout): ip for ip in tasks_to_submit}

        processed_count = 0
        total_tasks = len(future_to_server_ip)
        for future in as_completed(future_to_server_ip):
            server_ip = future_to_server_ip[future]
            stats = server_stats[server_ip]
            # Increment total_sent here reliably represents an attempt completion
            stats['total_sent'] += 1

            try:
                response_time_ms = future.result()
                if response_time_ms is not None:
                    stats['times'].append(response_time_ms)
                    stats['success_count'] += 1
                # else: query failed (timeout, etc.), already handled in query_server returning None
            except Exception as exc:
                # This catches unexpected errors during future.result() itself
                print(f'Server {server_ip} generated an exception retrieving result: {exc}')

            processed_count += 1
            # Print progress update periodically
            if processed_count % 100 == 0 or processed_count == total_tasks:
                 print(f"  Processed {processed_count}/{total_tasks} queries...")

    print("Analysis complete. Calculating final results...")
    results = []
    # Use the original server_ips list to ensure order and inclusion
    for server_ip in server_ips:
        stats = server_stats[server_ip]
        original_line = servers_map[server_ip] # Get the original line back

        if stats['success_count'] > 0:
            avg_time = statistics.mean(stats['times'])
        else:
            avg_time = 0.0 # Use 0.0 for simplicity in CSV when no successful queries

        # Calculate reliability based on successful queries vs the number requested
        reliability = (stats['success_count'] / num_requests) * 100 if num_requests > 0 else 0.0

        results.append({
            'Server IP': server_ip,
            'Server Info': original_line, # Add the original line here
            'Average Response Time (ms)': f"{avg_time:.2f}",
            'Reliability (%)': f"{reliability:.2f}",
            'Successful Queries': stats['success_count'],
            'Total Queries Attempted': num_requests # Reflects the target number of queries
        })

    # Sort results: Primary: Reliability (desc), Secondary: Avg Time (asc)
    results.sort(key=lambda x: (float(x['Reliability (%)']), float(x['Average Response Time (ms)'])), reverse=False) # Sort ascending time
    results.sort(key=lambda x: float(x['Reliability (%)']), reverse=True) # Then sort descending reliability

    return results


def write_results_to_csv(results, output_file):
    """Writes the analysis results to a CSV file."""
    if not results:
        print("No results to write.")
        return

    fieldnames = results[0].keys()
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        print(f"Results successfully written to {output_file}")
    except IOError as e:
        print(f"Error writing results to CSV file {output_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while writing CSV: {e}")


def main():
    """Main function to orchestrate the analysis."""
    args = parse_arguments()
    servers_map = read_servers(args.input_file)

    if not servers_map:
        return # Exit if no servers were read

    analysis_results = analyze_servers(
        servers_map=servers_map,
        num_requests=args.num_requests,
        domain=args.domain,
        record_type=args.record_type,
        timeout=args.timeout,
        max_workers=args.workers
    )

    write_results_to_csv(analysis_results, args.output_file)

if __name__ == "__main__":
    main()
