import asyncio
import httpx
import yaml
import os
from urllib.parse import urlparse, unquote

async def fetch_and_convert(session, url):
    """
    Fetches content from a given URL and attempts to convert it to Clash YAML
    using a public subconverter API.
    """
    print(f"Fetching and converting from {url} using subconverter API")
    try:
        # IMPORTANT: Choose a reliable public subconverter API.
        # You might need to try a few or consider deploying your own for stability.
        # Examples:
        # "https://sub.xeton.dev/sub"
        # "https://api.v1.mk/sub"
        # "https://sub.ops.love/sub"
        subconverter_api_base = "https://sub.ops.love/sub" # Recommended for now, but test it!
        
        # Construct the URL for the subconverter API
        # target=clash ensures the output is Clash-compatible YAML
        # url=<original_subscription_link> passes your source link to the API
        # You can add other parameters if the API supports them, e_g_ &insert=false&emoji=true
        api_url = f"{subconverter_api_base}?target=clash&url={url}"

        # Send the request to the subconverter API
        # Increased timeout as conversion might take longer
        response = await session.get(api_url, timeout=60) 
        response.raise_for_status() # Raises an exception for 4xx/5xx responses
        
        content = await response.text() # Get the converted YAML content

        # The subconverter API usually returns a complete Clash YAML configuration.
        # We'll directly attempt to load it and extract the proxies.
        try:
            clash_config = yaml.safe_load(content)
            if isinstance(clash_config, dict) and 'proxies' in clash_config:
                # Successfully parsed Clash configuration
                return url, clash_config['proxies'] # Return the list of proxy nodes
            else:
                print(f"Subconverter API returned unexpected YAML structure for {url}. Content: {content[:200]}...")
                return url, []
        except yaml.YAMLError as ye:
            print(f"Subconverter API returned invalid YAML for {url}: {ye}. Content: {content[:200]}...")
            return url, []

    except httpx.RequestError as e:
        print(f"Error fetching or converting {url} via subconverter API: {e}")
        return url, []
    except Exception as e:
        print(f"An unexpected error occurred for {url} during subconverter API call: {e}")
        return url, []

async def main():
    urls = [
        "https://igdux.top/~250630",
        "https://igdux.top/~250701-534",
        "https://igdux.top/~250717",
        "https://igdux.top/~250719",
        "https://igdux.top/~ha_250718",
        "https://igdux.top/RDpP",
        "https://igdux.top/XGEN",
        "https://igdux.top/zzCe",
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
        "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/output/all_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/data/all_unique_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/merged_configs.txt",
        "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list_raw.txt",
        "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    ]

    output_dir = "sc"
    os.makedirs(output_dir, exist_ok=True)

    async with httpx.AsyncClient() as session:
        tasks = [fetch_and_convert(session, url) for url in urls]
        results = await asyncio.gather(*tasks)

    for url, nodes in results:
        if not nodes:
            print(f"No nodes found or error for {url}. Skipping file creation.")
            continue

        # Determine filename based on the URL
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.split('/')
        
        # Get the last segment of the path, or sanitized hostname if path is empty
        if path_segments and path_segments[-1]:
            filename = path_segments[-1]
            if filename.endswith(('.yml', '.yaml', '.txt')):
                filename = filename.rsplit('.', 1)[0] # Remove original extension if present
        else:
            # Fallback to a sanitized hostname if no meaningful path
            filename = parsed_url.hostname.replace('.', '_').replace('-', '_')

        output_filename = os.path.join(output_dir, f"{filename}.yaml")
        
        # Ensure 'proxies' is the root key for Clash compatibility
        clash_config = {'proxies': nodes}

        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                yaml.dump(clash_config, f, allow_unicode=True, indent=2, sort_keys=False)
            print(f"Successfully saved {len(nodes)} nodes from {url} to {output_filename}")
        except Exception as e:
            print(f"Error saving nodes to {output_filename}: {e}")

if __name__ == "__main__":
    asyncio.run(main())
