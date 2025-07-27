import yaml
import requests
import time
import argparse
import asyncio
import aiohttp
from urllib.parse import urlparse

# Define constants
CLASH_API_VERSION = "v1"

def parse_args():
    parser = argparse.ArgumentParser(description="Speed test and sort Clash nodes via Clash API.")
    parser.add_argument("--clash-url", type=str, default="http://127.0.0.1:9090",
                        help="Clash external controller API address, e.g., http://127.0.0.1:9090")
    parser.add_argument("--clash-secret", type=str, default="your_secret_token_here", # *** IMPORTANT: REPLACE WITH YOUR ACTUAL SECURE KEY ***
                        help="Clash external controller secret key")
    parser.add_argument("--input-file", type=str, required=True,
                        help="Path to the YAML file containing nodes to be tested")
    parser.add_argument("--output-file", type=str, required=True,
                        help="Output path for the speed-tested and sorted YAML file")
    parser.add_argument("--timeout", type=int, default=5000,
                        help="Latency test timeout in milliseconds")
    parser.add_argument("--concurrent", type=int, default=10,
                        help="Number of concurrent tests")
    parser.add_argument("--max-latency", type=int, default=3000,
                        help="Filter out nodes with latency higher than this value (milliseconds)")
    parser.add_argument("--min-download", type=float, default=0.0,
                        help="Filter out nodes with download speed lower than this value (MB/s). Note: Current version does not support actual download speed testing.")
    parser.add_argument("--min-upload", type=float, default=0.0,
                        help="Filter out nodes with upload speed lower than this value (MB/s). Note: Current version does not support actual upload speed testing.")
    parser.add_argument("--sort", type=str, default="latency",
                        choices=["latency", "download", "upload"],
                        help="Sorting method: latency (default). Current version only supports sorting by latency.")
    parser.add_argument("--rename", action="store_true",
                        help="Whether to append speed information to node names")
    return parser.parse_args()

def get_clash_api_headers(secret):
    """Generates headers for Clash API requests, including the secret."""
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    return headers

def get_proxies_from_config(file_path):
    """Reads proxy nodes from a YAML configuration file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    if not config or 'proxies' not in config:
        print(f"Warning: No 'proxies' key found in '{file_path}' or file is empty.")
        return []
    return config['proxies']

async def test_proxy_latency_async(session, clash_url, secret, proxy_name, timeout_ms):
    """Asynchronously tests the latency of a single proxy."""
    # Mihomo's /proxies/{name}/delay API expects a URL to test against.
    # Using Google's 204 endpoint is a common practice.
    url = f"{clash_url}/{CLASH_API_VERSION}/proxies/{proxy_name}/delay?timeout={timeout_ms}&url=http://www.google.com/generate_204"
    headers = get_clash_api_headers(secret)
    try:
        # ClientTimeout includes both connect and read timeouts. Add a buffer for network overhead.
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_ms/1000 + 5)) as response:
            response.raise_for_status() # Raises an exception for HTTP errors (4xx or 5xx)
            data = await response.json()
            if 'delay' in data:
                return proxy_name, data['delay']
    except aiohttp.client_exceptions.ClientError as e:
        print(f"Error: Request error while testing '{proxy_name}' latency: {e}")
    except asyncio.TimeoutError:
        print(f"Warning: Timeout while testing '{proxy_name}' latency.")
    except Exception as e:
        print(f"Error: An unknown error occurred while testing '{proxy_name}' latency: {e}")
    return proxy_name, -1 # Return -1 to indicate failure

async def run_tests_concurrently(proxies, clash_url, secret, timeout_ms, concurrent_limit):
    """Runs latency tests on proxies concurrently."""
    tested_results = []
    # Use TCPConnector to limit concurrent connections per host
    connector = aiohttp.TCPConnector(limit_per_host=concurrent_limit, ssl=False) 
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for proxy in proxies:
            proxy_name = proxy.get('name')
            if proxy_name:
                tasks.append(test_proxy_latency_async(session, clash_url, secret, proxy_name, timeout_ms))
        
        # Process tasks as they complete
        for i, task in enumerate(asyncio.as_completed(tasks)):
            proxy_name, latency = await task
            original_proxy = next((p for p in proxies if p.get('name') == proxy_name), None)
            if original_proxy:
                if latency != -1:
                    print(f"[{i+1}/{len(proxies)}] Node: {proxy_name}, Latency: {latency}ms")
                    original_proxy['latency'] = latency
                    # Placeholders as real download/upload speed testing is not implemented via API
                    original_proxy['download_speed'] = 0.0 
                    original_proxy['upload_speed'] = 0.0
                    tested_results.append(original_proxy)
                else:
                    print(f"[{i+1}/{len(proxies)}] Node: {proxy_name}, Speed test failed or timed out, skipping.")
            else:
                print(f"Warning: Test result for unknown proxy name: {proxy_name}")
    return tested_results

def main():
    args = parse_args()

    # Read proxy nodes from the input YAML file
    print(f"Reading proxy nodes from '{args.input_file}'...")
    proxies = get_proxies_from_config(args.input_file)
    if not proxies:
        print("No proxy nodes found or input file format is incorrect.")
        # Create an empty output file to ensure workflow completion
        with open(args.output_file, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
        return

    clash_url = args.clash_url
    clash_secret = args.clash_secret
    
    # Validate if Clash core has loaded all proxies
    try:
        proxies_status_url = f"{clash_url}/{CLASH_API_VERSION}/proxies"
        headers = get_clash_api_headers(clash_secret)
        response = requests.get(proxies_status_url, headers=headers, timeout=10)
        response.raise_for_status() # Checks for HTTP errors
        current_proxies_info = response.json().get('proxies', {})
        print(f"Clash core has loaded {len(current_proxies_info)} proxies.")
        
        initial_proxy_names = {p['name'] for p in proxies if 'name' in p}
        clash_loaded_proxy_names = set(current_proxies_info.keys())

        missing_nodes = list(initial_proxy_names - clash_loaded_proxy_names)
        if missing_nodes:
            print(f"Warning: The following nodes were not found in Clash core and may not be testable: {missing_nodes[:5]}...") # Show first 5 missing nodes
            proxies = [p for p in proxies if p.get('name') in clash_loaded_proxy_names] # Filter out nodes not loaded by Mihomo
            if not proxies:
                print("All nodes were missing from Clash core, cannot proceed with speed test.")
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
                return
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to Clash API or get proxy status: {e}")
        print("Ensure Mihomo Core is running correctly and its configuration (mihomo_config.yaml) is valid.")
        with open(args.output_file, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
        exit(1)

    print(f"Total {len(proxies)} proxy nodes to be tested.")
    print(f"Concurrency: {args.concurrent}, Latency Timeout: {args.timeout}ms")

    # Perform speed tests (latency only for now)
    tested_proxies = asyncio.run(run_tests_concurrently(proxies, clash_url, clash_secret, args.timeout, args.concurrent))
    
    # Filter nodes based on latency (and placeholder speed values)
    filtered_proxies = []
    for proxy in tested_proxies:
        if proxy.get('latency', float('inf')) <= args.max_latency:
            # Current speed values are 0.0, so this part won't filter unless min_download/upload are > 0.0
            if proxy.get('download_speed', 0) >= args.min_download and \
               proxy.get('upload_speed', 0) >= args.min_upload:
                filtered_proxies.append(proxy)
            else:
                print(f"  - Node '{proxy.get('name')}' did not meet minimum speed requirements, skipping.")
        else:
            print(f"  - Node '{proxy.get('name')}' latency {proxy.get('latency')}ms exceeded max latency {args.max_latency}ms, skipping.")

    print(f"Speed test completed. {len(filtered_proxies)} nodes passed filtering.")

    # Sort nodes
    if args.sort == "latency":
        filtered_proxies.sort(key=lambda x: x.get('latency', float('inf')))
    elif args.sort == "download": # Placeholder sort, actual values are 0.0
        filtered_proxies.sort(key=lambda x: x.get('download_speed', 0), reverse=True)
    elif args.sort == "upload": # Placeholder sort, actual values are 0.0
        filtered_proxies.sort(key=lambda x: x.get('upload_speed', 0), reverse=True)

    # Rename nodes and prepare for output
    output_proxies = []
    for proxy in filtered_proxies:
        new_proxy = proxy.copy() # Create a copy to avoid modifying the original dict
        if args.rename:
            latency = new_proxy.get('latency', 'N/A')
            speed_info_parts = []
            if latency != 'N/A':
                speed_info_parts.append(f"L{latency}ms")
            
            speed_info = " ".join(speed_info_parts)
            if speed_info:
                new_proxy['name'] = f"{new_proxy['name']} ({speed_info})"
        
        # Remove temporary speed test data before writing to the config file
        new_proxy.pop('latency', None)
        new_proxy.pop('download_speed', None)
        new_proxy.pop('upload_speed', None)
        output_proxies.append(new_proxy)

    # Write the output YAML file
    output_config = {'proxies': output_proxies}
    with open(args.output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, sort_keys=False)
    print(f"Speed-tested and sorted nodes saved to '{args.output_file}'.")

if __name__ == "__main__":
    main()
