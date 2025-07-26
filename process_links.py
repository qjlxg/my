import asyncio
import httpx
import base64
import json
import yaml
import os
import re
from urllib.parse import urlparse, unquote

# 代理协议解析函数
def parse_node(node_string):
    if not node_string:
        return None

    node_data = {}
    try:
        if node_string.startswith("vmess://"):
            encoded_data = node_string[len("vmess://"):]
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            config = json.loads(decoded_data)
            node_data['name'] = config.get('ps', 'vmess-node')
            node_data['type'] = 'vmess'
            node_data['server'] = config.get('add')
            node_data['port'] = int(config.get('port'))
            node_data['uuid'] = config.get('id')
            node_data['alterId'] = int(config.get('aid', 0))
            node_data['cipher'] = 'auto' # Vmess usually handles cipher automatically
            node_data['tls'] = config.get('tls', '') == 'tls'
            node_data['skip-cert-verify'] = True if config.get('scy') == 1 else False
            if 'net' in config:
                node_data['network'] = config['net']
            if 'type' in config:
                node_data['ws-headers'] = {'Host': config['host']} if 'host' in config else {}
                node_data['ws-path'] = config['path']
            
        elif node_string.startswith("trojan://"):
            parsed_url = urlparse(node_string)
            password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            params = dict(qc.split("=") for qc in parsed_url.query.split("&")) if parsed_url.query else {}
            name = unquote(parsed_url.fragment) if parsed_url.fragment else f"trojan-{server}"

            node_data['name'] = name
            node_data['type'] = 'trojan'
            node_data['server'] = server
            node_data['port'] = port
            node_data['password'] = password
            node_data['tls'] = True
            node_data['skip-cert-verify'] = True if params.get('allowInsecure') == '1' else False
            if 'sni' in params:
                node_data['sni'] = params['sni']
            if 'fp' in params:
                node_data['fingerprint'] = params['fp']

        elif node_string.startswith("ss://"):
            # SS usually is base64(method:password@server:port)#name or base64(method:password@server:port)
            parts = node_string[len("ss://"):].split('#', 1)
            encoded_info = parts[0]
            name = unquote(parts[1]) if len(parts) > 1 else "shadowsocks-node"

            decoded_info = base64.b64decode(encoded_info + '==').decode('utf-8') # Add padding for base64
            
            # Use regex to extract method, password, server, port
            match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_info)
            if match:
                method, password, server, port = match.groups()
                node_data['name'] = name
                node_data['type'] = 'ss'
                node_data['server'] = server
                node_data['port'] = int(port)
                node_data['cipher'] = method
                node_data['password'] = password
            else:
                # Handle cases where password is not base64 encoded as part of the URL (e.g. ss://base64(server:port)#name and method/password in params)
                # This is a simpler parsing and may need more robust implementation for all SS forms.
                # For now, if the first part is just base64, assume the method and password are not encoded.
                match_no_auth = re.match(r'(.+?):(\d+)', decoded_info)
                if match_no_auth:
                    server, port = match_no_auth.groups()
                    # This branch needs an actual way to get cipher and password,
                    # which is usually from base64(method:password@server:port)
                    # or additional parameters in the fragment.
                    # For simplicity, if standard method:password is not found,
                    # this parse will be incomplete.
                    print(f"Warning: Incomplete SS node parsing for {node_string}. Method/password may be missing.")
                    return None
                else:
                    return None # Cannot parse this SS format

        elif node_string.startswith("ssr://"):
            # SSR parsing is more complex due to custom base64 and parameters
            encoded_data = node_string[len("ssr://"):]
            decoded_data = base64.b64decode(encoded_data + '==').decode('utf-8') # Add padding
            parts = decoded_data.split(':')
            if len(parts) >= 6:
                server = parts[0]
                port = int(parts[1])
                protocol = parts[2]
                method = parts[3]
                obfs = parts[4]
                password_base64 = parts[5].split('/?')[0]
                password = base64.b64decode(password_base64.replace('_', '/').replace('-', '+') + '==').decode('utf-8')
                
                params = {}
                if '/?' in decoded_data:
                    query_string = decoded_data.split('/?')[1]
                    params = dict(qc.split("=") for qc in query_string.split("&"))
                
                name = unquote(base64.b64decode(params.get('remarks', '').replace('_', '/').replace('-', '+') + '==').decode('utf-8')) if 'remarks' in params else f"ssr-{server}"
                obfsparam = unquote(base64.b64decode(params.get('obfsparam', '').replace('_', '/').replace('-', '+') + '==').decode('utf-8')) if 'obfsparam' in params else ''
                protparam = unquote(base64.b64decode(params.get('protoparam', '').replace('_', '/').replace('-', '+') + '==').decode('utf-8')) if 'protoparam' in params else ''

                node_data['name'] = name
                node_data['type'] = 'ssr'
                node_data['server'] = server
                node_data['port'] = port
                node_data['cipher'] = method
                node_data['password'] = password
                node_data['protocol'] = protocol
                node_data['protocol-param'] = protparam
                node_data['obfs'] = obfs
                node_data['obfs-param'] = obfsparam
            else:
                return None # Invalid SSR format

        elif node_string.startswith("vless://"):
            parsed_url = urlparse(node_string)
            uuid = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            name = unquote(parsed_url.fragment) if parsed_url.fragment else f"vless-{server}"
            
            params = dict(qc.split("=") for qc in parsed_url.query.split("&")) if parsed_url.query else {}

            node_data['name'] = name
            node_data['type'] = 'vless'
            node_data['server'] = server
            node_data['port'] = port
            node_data['uuid'] = uuid
            node_data['tls'] = True if params.get('security') == 'tls' else False
            node_data['skip-cert-verify'] = True if params.get('allowInsecure') == '1' else False
            if 'flow' in params:
                node_data['flow'] = params['flow']
            if 'sni' in params:
                node_data['sni'] = params['sni']
            if 'fp' in params:
                node_data['fingerprint'] = params['fp']
            if 'type' in params:
                node_data['network'] = params['type']
            if 'headerType' in params: # For HTTP/WS
                node_data['ws-headers'] = {'Host': params['host']} if 'host' in params else {}
                node_data['ws-path'] = params['path']
            elif 'path' in params: # For gRPC
                node_data['grpc-service-name'] = params['serviceName'] if 'serviceName' in params else ''
            
        elif node_string.startswith("hysteria2://"):
            parsed_url = urlparse(node_string)
            password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            name = unquote(parsed_url.fragment) if parsed_url.fragment else f"hysteria2-{server}"
            
            params = dict(qc.split("=") for qc in parsed_url.query.split("&")) if parsed_url.query else {}

            node_data['name'] = name
            node_data['type'] = 'hysteria2'
            node_data['server'] = server
            node_data['port'] = port
            node_data['password'] = password
            node_data['tls'] = True # Hysteria2 always uses TLS
            node_data['skip-cert-verify'] = True if params.get('insecure') == '1' else False
            if 'sni' in params:
                node_data['sni'] = params['sni']
            if 'alpn' in params:
                node_data['alpn'] = params['alpn'].split(',')
            if 'fastopen' in params:
                node_data['fast-open'] = True if params['fastopen'] == '1' else False
            
        else:
            # Attempt to decode as base64 first, then treat as plain text or YAML/JSON
            try:
                decoded_content = base64.b64decode(node_string + '==').decode('utf-8')
                # Try to parse the decoded content as a node, or as YAML/JSON
                if decoded_content.startswith(("vmess://", "trojan://", "ss://", "ssr://", "vless://", "hysteria2://")):
                    return parse_node(decoded_content)
                else:
                    # If it's not a known protocol, try parsing as YAML/JSON if it looks like one
                    return parse_plain_text(decoded_content)
            except Exception:
                # If not base64 or a known protocol, treat as plain text
                return parse_plain_text(node_string)

    except Exception as e:
        print(f"Error parsing node '{node_string}': {e}")
        return None
    return node_data

def parse_plain_text(content):
    # This function tries to parse plain text as either a direct node string,
    # or as YAML/JSON that might contain multiple nodes.
    # It's a best-effort approach.

    # Check if it's a single node string
    if content.startswith(("vmess://", "trojan://", "ss://", "ssr://", "vless://", "hysteria2://")):
        return parse_node(content)

    # Try to parse as YAML
    try:
        yaml_data = yaml.safe_load(content)
        if isinstance(yaml_data, dict) and 'proxies' in yaml_data:
            # Assume it's a Clash-like config with a list of proxies
            parsed_nodes = []
            for proxy_config in yaml_data['proxies']:
                # Clash config is already in a usable dict format
                parsed_nodes.append(proxy_config)
            return parsed_nodes
        elif isinstance(yaml_data, list):
            # Assume it's a list of nodes directly
            parsed_nodes = []
            for item in yaml_data:
                if isinstance(item, dict):
                    parsed_nodes.append(item)
                elif isinstance(item, str):
                    node = parse_node(item)
                    if node:
                        parsed_nodes.append(node)
            return parsed_nodes
    except yaml.YAMLError:
        pass # Not valid YAML

    # Try to parse as JSON
    try:
        json_data = json.loads(content)
        if isinstance(json_data, list):
            parsed_nodes = []
            for item in json_data:
                if isinstance(item, dict):
                    parsed_nodes.append(item)
                elif isinstance(item, str):
                    node = parse_node(item)
                    if node:
                        parsed_nodes.append(node)
            return parsed_nodes
        elif isinstance(json_data, dict) and 'proxies' in json_data:
             parsed_nodes = []
             for proxy_config in json_data['proxies']:
                 parsed_nodes.append(proxy_config)
             return parsed_nodes
    except json.JSONDecodeError:
        pass # Not valid JSON

    # If all else fails, assume it's just plain text and return it for further processing
    # or discard if not a recognizable node format
    return None


async def fetch_and_parse(session, url):
    print(f"Fetching from {url}")
    try:
        async with session.get(url, timeout=30) as response:
            response.raise_for_status()
            content = await response.text()
            
            all_nodes = []
            # First, try to parse the entire content as a single YAML or JSON structure (e.g., Clash config)
            parsed_structure = parse_plain_text(content)
            if isinstance(parsed_structure, list):
                all_nodes.extend(parsed_structure)
            elif isinstance(parsed_structure, dict): # Should only happen if it was a single node in the structure
                all_nodes.append(parsed_structure)
            else: # If not a YAML/JSON structure, try line by line
                lines = content.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        node = parse_node(line)
                        if node:
                            all_nodes.append(node)
                        else:
                            print(f"Could not parse line from {url}: {line[:50]}...") # Log problematic lines
            return url, all_nodes
    except httpx.RequestError as e:
        print(f"Error fetching {url}: {e}")
        return url, []
    except Exception as e:
        print(f"An unexpected error occurred for {url}: {e}")
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
        tasks = [fetch_and_parse(session, url) for url in urls]
        results = await asyncio.gather(*tasks)

    for url, nodes in results:
        if not nodes:
            print(f"No nodes found or error for {url}. Skipping file creation.")
            continue

        # Determine filename
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.split('/')
        
        # Get the last segment of the path, or hostname if path is empty
        if path_segments and path_segments[-1]:
            filename = path_segments[-1]
            if filename.endswith(('.yml', '.yaml', '.txt')):
                filename = filename.rsplit('.', 1)[0] # Remove original extension
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
