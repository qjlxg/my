import os
import requests
import yaml
import json
import re
import base64 # Need for encoding/decoding in some parsers
from urllib.parse import urlparse, parse_qs

# Configuration
CONFIG = [
    {"url": "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml", "type": "yaml_or_links"},
    {"url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml", "type": "clash_config"},
    {"url": "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt", "type": "links_only"},
    {"url": "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt", "type": "links_only"},
]
OUTPUT_FILE = "sc/all.yaml"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Supported protocols and their parsing functions
# Each function should return a dictionary representing the node, or None if parsing fails
NODE_PARSERS = {
    "ss": lambda url: parse_ss(url),
    "ssr": lambda url: parse_ssr(url),
    "vmess": lambda url: parse_vmess(url),
    "trojan": lambda url: parse_trojan(url),
    "vless": lambda url: parse_vless(url),
    "hy2": lambda url: parse_hysteria2(url),
    "tuic": lambda url: parse_tuic(url),
    "hysteria": lambda url: parse_hysteria(url),
}

# Regex to find common proxy link patterns
PROXY_LINK_REGEX = re.compile(r'(ss|ssr|vmess|trojan|vless|hy2|tuic|hysteria)://[^ ]+')


def debug_log(message):
    """Prints debug messages."""
    print(f"Debug: {message}")

def warning_log(message):
    """Prints warning messages."""
    print(f"Warning: {message}")

def error_log(message):
    """Prints error messages."""
    print(f"Error: {message}")

def fetch_content(url):
    """Fetches content from a given URL."""
    try:
        print(f"Fetching from {url}")
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        error_log(f"Failed to fetch {url}: {e}")
        return None

def preview_content(content):
    """Prints a preview of the fetched content."""
    lines = content.splitlines()
    print("--- Fetched Content Preview (First 10 lines) ---")
    for i, line in enumerate(lines[:10]):
        # Limit snippet length for display
        print(f"Line {i+1} (snippet): {line[:100]}...")
    print("--- End Content Preview ---")

def is_valid_yaml(content):
    """Checks if the content is valid full YAML."""
    try:
        debug_log("Attempting to parse as full YAML")
        # Use safe_load to prevent arbitrary code execution
        yaml.safe_load(content)
        return True
    except yaml.YAMLError as e:
        debug_log(f"Failed to parse as full YAML: {e}")
        return False

def is_valid_json(content):
    """Checks if the content is valid full JSON."""
    try:
        debug_log("Attempting to parse as full JSON")
        json.loads(content)
        return True
    except json.JSONDecodeError as e:
        debug_log(f"Failed to parse as full JSON: {e}")
        return False

def parse_yaml_nodes(content):
    """Parses YAML content and extracts proxy nodes."""
    try:
        data = yaml.safe_load(content)
        nodes = []
        # Handle Clash proxy-providers format
        if isinstance(data, dict) and "proxy-providers" in data:
            for provider_name, provider_info in data.get("proxy-providers", {}).items():
                if "proxies" in provider_info and isinstance(provider_info["proxies"], list):
                    nodes.extend(provider_info["proxies"])
        # Handle direct proxies list in YAML
        if isinstance(data, dict) and "proxies" in data:
            nodes.extend(data["proxies"])
        elif isinstance(data, list): # Direct list of proxy nodes
            nodes.extend(data)
        return nodes
    except yaml.YAMLError as e:
        warning_log(f"Could not parse YAML content: {e}")
        return []

def parse_clash_config(content):
    """Parses a Clash configuration YAML and extracts proxy nodes."""
    try:
        config = yaml.safe_load(content)
        nodes = []
        if isinstance(config, dict):
            # Extract from 'proxies' key
            if 'proxies' in config and isinstance(config['proxies'], list):
                nodes.extend(config['proxies'])
            # Extract from 'proxy-providers'
            if 'proxy-providers' in config and isinstance(config['proxy-providers'], dict):
                for provider_name, provider_data in config['proxy-providers'].items():
                    if 'proxies' in provider_data and isinstance(provider_data['proxies'], list):
                        nodes.extend(provider_data['proxies'])
        return nodes
    except yaml.YAMLError as e:
        warning_log(f"Could not parse Clash config (YAML): {e}")
        return []

def parse_single_proxy_link(link_str):
    """Parses a single proxy link string."""
    link_str = link_str.strip()
    if not link_str:
        return None

    if "://" not in link_str:
        return None # Not a valid link format

    protocol, _ = link_str.split("://", 1)
    protocol = protocol.lower()

    if protocol in NODE_PARSERS:
        try:
            node = NODE_PARSERS[protocol](link_str)
            if node:
                return node
            else:
                warning_log(f"Skipping unparseable {protocol} node from link: {link_str[:80]}...")
        except Exception as e:
            error_log(f"Error parsing {protocol} data '{link_str[:50]}...': {e}")
            warning_log(f"Skipping unparseable {protocol} node from link: {link_str[:80]}...")
    else:
        warning_log(f"Unsupported protocol '{protocol}' found in link: {link_str[:80]}...")
    return None

def parse_line_for_multiple_links(line):
    """
    Attempts to find and parse multiple proxy links within a single line.
    Returns a list of parsed nodes.
    """
    found_nodes = []
    # Find all occurrences of known proxy link patterns
    matches = list(PROXY_LINK_REGEX.finditer(line))

    if not matches:
        return found_nodes

    # Extract each matched link and parse it
    for match in matches:
        link = match.group(0).strip()
        node = parse_single_proxy_link(link)
        if node:
            found_nodes.append(node)
    
    if not found_nodes:
        warning_log(f"No nodes found in line after attempting regex match: {line[:100]}...")

    return found_nodes


# --- Proxy Protocol Parsers (KEEP AS IS FROM PREVIOUS RESPONSE) ---
# These functions should already be robust enough to parse individual, well-formed links.

def parse_ss(url):
    """Parses a Shadowsocks (SS) URL."""
    try:
        parsed = urlparse(url)
        # Decode base64 if it's there
        if parsed.netloc:
            try:
                # Attempt base64 decode (common for ss links with method/password in netloc)
                decoded_netloc = base64.urlsafe_b64decode(parsed.netloc + "==").decode('utf-8')
                parts = decoded_netloc.split('@')
                if len(parts) == 2:
                    method_password, server_port_str = parts
                    method, password = method_password.split(':', 1)
                else: # Fallback if base64 doesn't contain method:password
                    method, password = None, None
                    server_port_str = decoded_netloc
            except: # Not base64, direct parsing of netloc
                method, password = None, None
                server_port_str = parsed.netloc
        else: # Handle ss://server:port#name format without userinfo in netloc
            method, password = None, None
            server_port_str = parsed.path.lstrip('/')

        server, port = server_port_str.rsplit(':', 1)
        # Clean fragment from potential extra data after #
        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"SS-{server}:{port}"

        node = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method if method else "auto", # Default or detect if possible
            "password": password if password else "",
            "udp": True # Common for SS
        }
        # Add plugin if present in query parameters
        query_params = parse_qs(parsed.query)
        if 'plugin' in query_params:
            plugin_parts = query_params['plugin'][0].split(';')
            node['plugin'] = plugin_parts[0]
            if len(plugin_parts) > 1:
                # Parse plugin-opts from the rest of the string
                plugin_opts_str = ';'.join(plugin_parts[1:])
                plugin_opts_dict = {}
                for item in plugin_opts_str.split('&'):
                    if '=' in item:
                        k, v = item.split('=', 1)
                        plugin_opts_dict[k] = v
                node['plugin-opts'] = plugin_opts_dict
        return node
    except Exception as e:
        error_log(f"Failed to parse SS link: {url} - {e}")
        return None

def parse_ssr(url):
    """Parses a ShadowsocksR (SSR) URL."""
    try:
        if not url.startswith("ssr://"):
            return None
        encoded_part = url[len("ssr://"):]
        missing_padding = len(encoded_part) % 4
        if missing_padding:
            encoded_part += '=' * (4 - missing_padding)

        decoded_params = base64.urlsafe_b64decode(encoded_part).decode('utf-8')

        parts = decoded_params.split(':')
        if len(parts) < 6:
            raise ValueError("SSR link missing components")

        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        password_base64_part = parts[5]

        password = ""
        query_fragment = ""
        if '?' in password_base64_part:
            password_encoded, query_fragment = password_base64_part.split('?', 1)
            try:
                password = base64.urlsafe_b64decode(password_encoded + "==").decode('utf-8')
            except:
                password = password_encoded
        else:
            query_fragment = password_base64_part
            # In some SSR links, password might be directly in the 6th part if no query
            try:
                password = base64.urlsafe_b64decode(password_base64_part + "==").decode('utf-8')
            except:
                password = password_base64_part


        name = f"SSR-{server}:{port}"
        query_params = {}
        if '#' in query_fragment:
            query_part, fragment_part = query_fragment.split('#', 1)
            query_params = parse_qs(query_part)
            try:
                name = base64.urlsafe_b64decode(fragment_part + "==").decode('utf-8')
            except:
                name = fragment_part
        else:
            query_params = parse_qs(query_fragment)

        obfs_param = query_params.get('obfsparam', [''])[0]
        protocol_param = query_params.get('protoparam', [''])[0]

        node = {
            "name": name,
            "type": "ssr",
            "server": server,
            "port": port,
            "password": password,
            "cipher": method,
            "obfs": obfs,
            "obfs-param": obfs_param,
            "protocol": protocol,
            "protocol-param": protocol_param,
            "udp": True
        }
        return node
    except Exception as e:
        error_log(f"Failed to parse SSR link: {url} - {e}")
        return None

def parse_vmess(url):
    """Parses a Vmess URL."""
    try:
        if not url.startswith("vmess://"):
            return None
        encoded_json = url[len("vmess://"):]
        decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
        config = json.loads(decoded_json_str)

        node = {
            "name": config.get("ps", f"Vmess-{config.get('add')}:{config.get('port')}"),
            "type": "vmess",
            "server": config.get("add"),
            "port": int(config.get("port")),
            "uuid": config.get("id"),
            "alterId": int(config.get("aid", 0)),
            "cipher": "auto",
            "udp": True,
            "network": config.get("net", "tcp"),
        }

        if config.get("tls") == "tls":
            node["tls"] = True
            node["servername"] = config.get("sni", config.get("host"))
            if config.get("allowInsecure"):
                node["skip-cert-verify"] = True

        if node["network"] == "ws":
            ws_opts = {}
            if config.get("path"):
                ws_opts["path"] = config["path"]
            if config.get("headers"):
                ws_opts["headers"] = config["headers"]
            elif config.get("host"): # Older Vmess links might use host for WS header
                ws_opts["headers"] = {"Host": config["host"]}
            if ws_opts:
                node["ws-opts"] = ws_opts
        elif node["network"] == "http":
            http_opts = {}
            if config.get("path"):
                http_opts["path"] = config["path"].split(',')
            if config.get("headers"):
                http_opts["headers"] = config["headers"]
            elif config.get("host"):
                http_opts["headers"] = {"Host": config["host"].split(',')}
            if http_opts:
                node["http-opts"] = http_opts
        elif node["network"] == "grpc":
            grpc_opts = {}
            if config.get("serviceName"):
                grpc_opts["serviceName"] = config["serviceName"]
            if grpc_opts:
                node["grpc-opts"] = grpc_opts
        elif node["network"] == "h2":
            h2_opts = {}
            if config.get("path"):
                h2_opts["path"] = config["path"]
            if config.get("host"):
                h2_opts["host"] = config["host"].split(',')
            if h2_opts:
                node["h2-opts"] = h2_opts

        return node
    except Exception as e:
        error_log(f"Failed to parse Vmess link: {url} - {e}")
        return None

def parse_trojan(url):
    """Parses a Trojan URL."""
    try:
        parsed = urlparse(url)
        password = parsed.username or ""
        server = parsed.hostname
        port = parsed.port
        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"Trojan-{server}:{port}" # Clean fragment

        node = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": True,
            "network": "tcp",
        }

        query_params = parse_qs(parsed.query)

        node["tls"] = True
        node["servername"] = query_params.get("sni", [server])[0]
        if "allowInsecure" in query_params:
            node["skip-cert-verify"] = True

        transport_type = query_params.get("type", ["tcp"])[0]
        node["network"] = transport_type

        if transport_type == "ws":
            ws_opts = {}
            if "path" in query_params:
                ws_opts["path"] = query_params["path"][0]
            if "host" in query_params:
                ws_opts["headers"] = {"Host": query_params["host"][0]}
            if ws_opts:
                node["ws-opts"] = ws_opts
        elif transport_type == "grpc":
            grpc_opts = {}
            if "serviceName" in query_params:
                grpc_opts["serviceName"] = query_params["serviceName"][0]
            if grpc_opts:
                node["grpc-opts"] = grpc_opts
        elif transport_type == "h2":
            h2_opts = {}
            if "path" in query_params:
                h2_opts["path"] = query_params["path"][0]
            if "host" in query_params:
                h2_opts["host"] = query_params["host"][0]
            if h2_opts:
                node["h2-opts"] = h2_opts

        return node
    except Exception as e:
        error_log(f"Failed to parse Trojan link: {url} - {e}")
        return None

def parse_vless(url):
    """Parses a VLESS URL."""
    try:
        parsed = urlparse(url)
        uuid = parsed.username or ""
        server = parsed.hostname
        port = parsed.port
        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"Vless-{server}:{port}"

        node = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
            "network": "tcp",
        }

        query_params = parse_qs(parsed.query)

        security = query_params.get("security", ["none"])[0]
        if security == "tls":
            node["tls"] = True
            node["servername"] = query_params.get("sni", [server])[0]
            if "flow" in query_params:
                node["flow"] = query_params["flow"][0]
            if "allowInsecure" in query_params:
                node["skip-cert-verify"] = True
        elif security == "reality":
            node["tls"] = True
            node["servername"] = query_params.get("sni", [server])[0]
            node["reality-opts"] = {
                "publicKey": query_params.get("pbk", [""])[0],
                "shortId": query_params.get("sid", [""])[0],
                "spiderX": query_params.get("spx", [""])[0]
            }
            if "fp" in query_params:
                node["reality-opts"]["fingerprint"] = query_params["fp"][0]
            if "flow" in query_params:
                node["flow"] = query_params["flow"][0]
            if "allowInsecure" in query_params: # Although Reality generally handles this
                node["skip-cert-verify"] = True

        transport_type = query_params.get("type", ["tcp"])[0]
        node["network"] = transport_type

        if transport_type == "ws":
            ws_opts = {}
            if "path" in query_params:
                ws_opts["path"] = query_params["path"][0]
            if "host" in query_params:
                ws_opts["headers"] = {"Host": query_params["host"][0]}
            if ws_opts:
                node["ws-opts"] = ws_opts
        elif transport_type == "grpc":
            grpc_opts = {}
            if "serviceName" in query_params:
                grpc_opts["serviceName"] = query_params["serviceName"][0]
            if grpc_opts:
                node["grpc-opts"] = grpc_opts
        elif transport_type == "h2":
            h2_opts = {}
            if "path" in query_params:
                h2_opts["path"] = query_params["path"][0]
            if "host" in query_params:
                h2_opts["host"] = query_params["host"][0]
            if h2_opts:
                node["h2-opts"] = h2_opts

        return node
    except Exception as e:
        error_log(f"Failed to parse VLESS link: {url} - {e}")
        return None

def parse_hysteria2(url):
    """Parses a Hysteria2 (hy2) URL."""
    try:
        parsed = urlparse(url)
        server = parsed.hostname
        try:
            port = int(parsed.port)
        except (ValueError, TypeError):
            raise ValueError(f"Port could not be cast to integer value as '{parsed.port}'")

        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"Hysteria2-{server}:{port}"

        node = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "udp": True,
        }

        query_params = parse_qs(parsed.query)

        node["password"] = query_params.get("password", [""])[0]
        node["obfs"] = query_params.get("obfs", ["none"])[0]
        if node["obfs"] == "salamander":
            node["obfs-password"] = query_params.get("obfsParam", [""])[0]
        
        node["tls"] = True
        node["servername"] = query_params.get("sni", [server])[0]
        if query_params.get("insecure", ["0"])[0] == "1":
            node["skip-cert-verify"] = True
        
        node["alpn"] = query_params.get("alpn", ["h3"])[0].split(',')
        node["fast-open"] = query_params.get("fastopen", ["1"])[0] == "1"
        node["mptcp"] = query_params.get("mptcp", ["0"])[0] == "1"
        
        if "up" in query_params:
            node["up"] = int(query_params["up"][0])
        if "down" in query_params:
            node["down"] = int(query_params["down"][0])

        return node
    except Exception as e:
        error_log(f"Error parsing hysteria2 data '{url[:50]}...': {e}")
        return None

def parse_tuic(url):
    """Parses a TUIC URL."""
    try:
        parsed = urlparse(url)
        
        auth_part = parsed.netloc.split('@')[0]
        uuid = ""
        password = ""
        if ':' in auth_part:
            uuid, password = auth_part.split(':', 1)
        elif auth_part:
            try:
                decoded_auth = base64.urlsafe_b64decode(auth_part + "==").decode('utf-8')
                if ':' in decoded_auth:
                    uuid, password = decoded_auth.split(':', 1)
                else:
                    uuid = decoded_auth
            except:
                uuid = auth_part

        server = parsed.hostname
        port = parsed.port
        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"Tuic-{server}:{port}"

        node = {
            "name": name,
            "type": "tuic",
            "server": server,
            "port": port,
            "uuid": uuid,
            "password": password,
            "udp": True,
        }

        query_params = parse_qs(parsed.query)

        node["tls"] = True
        node["servername"] = query_params.get("sni", [server])[0]
        node["alpn"] = query_params.get("alpn", ["h3"])[0].split(',')
        if query_params.get("insecure", ["0"])[0] == "1":
            node["skip-cert-verify"] = True

        node["congestion-controller"] = query_params.get("cc", ["bbr"])[0]
        node["enable-fast-open"] = query_params.get("fo", ["1"])[0] == "1"
        node["reduce-rtt"] = query_params.get("rr", ["0"])[0] == "1"
        node["max-udp-relay-datagram-size"] = int(query_params.get("mudp", ["1500"])[0])

        return node
    except Exception as e:
        error_log(f"Failed to parse TUIC link: {url} - {e}")
        return None

def parse_hysteria(url):
    """Parses a Hysteria (v1) URL."""
    try:
        parsed = urlparse(url)
        server = parsed.hostname
        port = parsed.port
        name = parsed.fragment.split(' ')[0].split(': ')[0].strip() if parsed.fragment else f"Hysteria-{server}:{port}"

        node = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": port,
            "udp": True,
        }

        query_params = parse_qs(parsed.query)

        node["auth"] = query_params.get("auth", [""])[0]
        
        node["tls"] = True
        node["servername"] = query_params.get("sni", [server])[0]
        if query_params.get("insecure", ["0"])[0] == "1":
            node["skip-cert-verify"] = True
        
        node["alpn"] = query_params.get("alpn", ["hy2"])[0].split(',')
        
        node["up"] = int(query_params.get("up", ["100"])[0])
        node["down"] = int(query_params.get("down", ["100"])[0])
        node["obfs"] = query_params.get("obfs", ["none"])[0]
        node["obfs-uri"] = query_params.get("obfsParam", [""])[0]
        
        return node
    except Exception as e:
        error_log(f"Failed to parse Hysteria link: {url} - {e}")
        return None

# --- End Proxy Protocol Parsers ---


def process_content(content, content_type):
    """Processes fetched content based on its type."""
    nodes = []

    if not content:
        return nodes

    preview_content(content)

    # Try to parse as full YAML or JSON first for structured configs
    if is_valid_yaml(content) and content_type in ["yaml_or_links", "clash_config"]:
        print("Content is valid full YAML.")
        if content_type == "clash_config":
            nodes.extend(parse_clash_config(content))
        else:
            nodes.extend(parse_yaml_nodes(content))
    elif is_valid_json(content) and content_type in ["yaml_or_links"]:
        print("Content is valid full JSON.")
        try:
            json_data = json.loads(content)
            if isinstance(json_data, list):
                nodes.extend(json_data)
            elif isinstance(json_data, dict) and "proxies" in json_data and isinstance(json_data["proxies"], list):
                nodes.extend(json_data["proxies"])
            else:
                warning_log("JSON content is not a direct list of nodes or a Clash-like config. Attempting line-by-line.")
                # Fallback to line-by-line if JSON structure is unexpected
                print("Content is neither valid full YAML nor JSON, attempting line-by-line parsing for individual node links.")
                for line in content.splitlines():
                    nodes.extend(parse_line_for_multiple_links(line)) # Use the new function
        except json.JSONDecodeError:
            warning_log("Could not parse JSON content. Attempting line-by-line.")
            print("Content is neither valid full YAML nor JSON, attempting line-by-line parsing for individual node links.")
            for line in content.splitlines():
                nodes.extend(parse_line_for_multiple_links(line)) # Use the new function
    else:
        # Fallback for when content is not a full YAML/JSON config, or for link-only types
        print("Content is neither valid full YAML nor JSON, attempting line-by-line parsing for individual node links.")
        # Some config files might be a single-line flattened YAML/JSON for proxies
        if content_type in ["yaml_or_links", "clash_config"] and (content.startswith("proxies:") or content.startswith("proxy-providers:")):
            warning_log("Attempting to parse content as a single-line (flattened) YAML-like string.")
            try:
                single_line_yaml_content = f"top_level:\n  {content}"
                parsed_single = yaml.safe_load(single_line_yaml_content)
                if isinstance(parsed_single, dict) and 'top_level' in parsed_single:
                    potential_nodes = parsed_single['top_level']
                    if 'proxies' in potential_nodes and isinstance(potential_nodes['proxies'], list):
                        nodes.extend(potential_nodes['proxies'])
                    elif 'proxy-providers' in potential_nodes and isinstance(potential_nodes['proxy-providers'], dict):
                        for provider_name, provider_data in potential_nodes['proxy-providers'].items():
                            if 'proxies' in provider_data and isinstance(provider_data['proxies'], list):
                                nodes.extend(provider_data['proxies'])
                if nodes:
                    return nodes
                else:
                    warning_log("Could not parse line 1 as a node: " + content[:100] + "...")
            except yaml.YAMLError as e:
                warning_log(f"Failed to parse as single-line YAML: {e}")
                warning_log("Could not parse line 1 as a node: " + content[:100] + "...")
        else:
            warning_log("No nodes found after attempting all parsing methods.")

        # Always attempt line-by-line parsing as a final fallback
        for line in content.splitlines():
            nodes.extend(parse_line_for_multiple_links(line)) # Use the new function
    return nodes

def filter_unique_nodes(nodes):
    """Filters out duplicate nodes based on a simplified representation."""
    unique_nodes = []
    seen_nodes = set()

    for node in nodes:
        # Create a tuple of immutable properties for hashing
        node_id_parts = []
        node_id_parts.append(node.get("type"))
        node_id_parts.append(node.get("server"))
        node_id_parts.append(node.get("port"))
        node_id_parts.append(node.get("uuid"))
        node_id_parts.append(node.get("password"))
        node_id_parts.append(node.get("cipher"))
        # Add a unique identifier for Reality for better deduplication
        if node.get("type") == "vless" and "reality-opts" in node:
            node_id_parts.append(node["reality-opts"].get("publicKey"))

        node_id = tuple(node_id_parts)

        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            unique_nodes.append(node)
    return unique_nodes

def save_nodes_to_yaml(nodes, filename):
    """Saves a list of nodes to a YAML file."""
    output_dir = os.path.dirname(filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    clash_format = {"proxies": nodes}

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_format, f, allow_unicode=True, sort_keys=False)
        print(f"Successfully saved {len(nodes)} unique nodes to {filename}")
    except Exception as e:
        error_log(f"Failed to save nodes to {filename}: {e}")

def main():
    """Main function to orchestrate fetching, parsing, and saving."""
    all_fetched_nodes = []

    for config_item in CONFIG:
        url = config_item["url"]
        content_type = config_item["type"]
        content = fetch_content(url)
        if content:
            parsed_nodes = process_content(content, content_type)
            all_fetched_nodes.extend(parsed_nodes)
        else:
            warning_log(f"No content fetched from {url}, skipping processing for this URL.")

    print(f"Total nodes fetched before filtering: {len(all_fetched_nodes)}")
    unique_nodes = filter_unique_nodes(all_fetched_nodes)
    print(f"Filtered down to {len(unique_nodes)} unique and valid nodes.")

    if unique_nodes:
        save_nodes_to_yaml(unique_nodes, OUTPUT_FILE)
    else:
        warning_log("No unique and valid nodes found to save.")

if __name__ == "__main__":
    main()
