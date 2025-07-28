import aiohttp
import asyncio
import base64
import json
import yaml
import os
import re
import platform
import logging
from urllib.parse import urlparse, unquote, parse_qs
from typing import List, Dict, Any, Optional
from collections import defaultdict

# --- Configuration ---
CONFIG = {
    "ENABLE_REGION_FILTERING": False,
    "SUPPORTED_PROTOCOLS": {'hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless'},
    "DOMESTIC_KEYWORDS": [
        'cn', 'china', '中国', '大陆', 'tencent', 'aliyun', '华为云', '移动', '联通', '电信',
        '北京', '上海', '广东', '江苏', '浙江', '四川', '重庆', '湖北', '湖南', '福建', '山东',
        '河南', '河北', '山西', '陕西', '辽宁', '吉林', '黑龙江', '安徽', '江西', '广西', '云南',
        '贵州', '甘肃', '青海', '宁夏', '新疆', '西藏', '内蒙古', '天津', '海南', 'hk', 'tw', 'mo'
    ],
    "KEEP_REGIONS": ['sg', 'jp', 'kr', 'ru'],
    "VMESS_CIPHERS": [
        'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305', 'aes-256-gcm'
    ],
    "FETCH_TIMEOUT": 30,
}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

async def fetch_url(session: aiohttp.ClientSession, url: str) -> str:
    """Fetch content from a URL asynchronously."""
    logger.info(f"Fetching from {url}")
    try:
        async with session.get(url, timeout=CONFIG["FETCH_TIMEOUT"]) as response:
            if response.status == 200:
                content = await response.text()
                return re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)
            logger.warning(f"Failed to fetch {url}: Status {response.status}")
            return ""
    except Exception as e:
        logger.error(f"Error fetching {url}: {str(e)}")
        return ""

def generate_node_name(protocol: str, server: Optional[str] = None, port: Optional[int] = None) -> str:
    """Generate a default node name."""
    server_str = server or "unknown_server"
    port_str = str(port) if port is not None else "unknown_port"
    return f"{protocol}-{server_str}:{port_str}"

def ensure_node_name(node: Dict[str, Any], protocol: str) -> Dict[str, Any]:
    """Ensure node dictionary has a 'name' field."""
    if 'name' not in node or not node['name']:
        node['name'] = generate_node_name(protocol, node.get('server'), node.get('port'))
    return node

def decode_base64(data: str) -> Optional[str]:
    """Safely decode base64 string."""
    try:
        return base64.b64decode(data.strip() + '==').decode('utf-8')
    except Exception as e:
        logger.error(f"Base64 decode error: {str(e)}")
        return None

# Protocol parsing handlers
PROTOCOL_PARSERS = {
    'vmess': lambda data: parse_vmess(data),
    'trojan': lambda data: parse_trojan(data),
    'ss': lambda data: parse_ss(data),
    'vless': lambda data: parse_vless(data),
    'hysteria2': lambda data: parse_hysteria2(data),
    'ssr': lambda data: parse_ssr(data)
}

def parse_vmess(data: str) -> Optional[Dict[str, Any]]:
    """Parse vmess protocol data."""
    decoded = decode_base64(data)
    if not decoded:
        return None
    try:
        config = json.loads(decoded)
        server, port = config.get('add'), config.get('port')
        if not server or not port:
            logger.error(f"Invalid vmess: missing server or port")
            return None
        node = {
            'name': config.get('ps', generate_node_name('vmess', server, port)),
            'type': 'vmess',
            'server': server,
            'port': int(port),
            'uuid': config.get('id', ''),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('type', 'auto')
        }
        if config.get('tls') == 'tls':
            node.update({
                'tls': True,
                'skip-cert-verify': bool(config.get('scy', False)),
                'sni': config.get('host'),
                'client-fingerprint': config.get('fp') or config.get('fingerprint')
            })
        network = config.get('net')
        if network:
            node['network'] = network
            if network == 'ws':
                node.update({
                    'ws-path': config.get('path', '/'),
                    'ws-headers': {'Host': config['host']} if config.get('host') else {}
                })
            elif network == 'grpc':
                node['grpc-service-name'] = config.get('path', '')
        return ensure_node_name(node, 'vmess')
    except Exception as e:
        logger.error(f"Error parsing vmess: {str(e)}")
        return None

def parse_trojan(data: str) -> Optional[Dict[str, Any]]:
    """Parse trojan protocol data."""
    try:
        parsed_url = urlparse(f"trojan://{data.strip()}")
        password, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port or 443
        if not all([server, port, password]):
            logger.error(f"Invalid trojan: missing server, port, or password")
            return None
        params = parse_qs(parsed_url.query)
        node = {
            'name': unquote(parsed_url.fragment) or generate_node_name('trojan', server, port),
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'tls': True,
            'skip-cert-verify': params.get('allowInsecure', ['0'])[0] == '1',
            'sni': params.get('sni', [''])[0],
            'client-fingerprint': params.get('fp', [''])[0],
            'alpn': params.get('alpn', [''])[0].split(',') if params.get('alpn') else []
        }
        return ensure_node_name(node, 'trojan')
    except Exception as e:
        logger.error(f"Error parsing trojan: {str(e)}")
        return None

def parse_ss(data: str) -> Optional[Dict[str, Any]]:
    """Parse ss protocol data."""
    try:
        parts = data.strip().split('#', 1)
        decoded = decode_base64(parts[0])
        if not decoded:
            return None
        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded)
        if not match:
            logger.error(f"SS format not recognized")
            return None
        method, password, server, port = match.groups()
        if not all([server, port, method, password]):
            logger.error(f"Invalid ss: missing server, port, method, or password")
            return None
        node = {
            'name': unquote(parts[1]) if len(parts) > 1 else generate_node_name('ss', server, port),
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method or 'auto',
            'password': password
        }
        return ensure_node_name(node, 'ss')
    except Exception as e:
        logger.error(f"Error parsing ss: {str(e)}")
        return None

def parse_vless(data: str) -> Optional[Dict[str, Any]]:
    """Parse vless protocol data."""
    try:
        parsed_url = urlparse(f"vless://{data.strip()}")
        uuid, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port or 443
        if not all([server, port, uuid]):
            logger.error(f"Invalid vless: missing server, port, or uuid")
            return None
        params = parse_qs(parsed_url.query)
        node = {
            'name': unquote(parsed_url.fragment) or generate_node_name('vless', server, port),
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid
        }
        security = params.get('security', [''])[0]
        if security == 'tls':
            node.update({
                'tls': True,
                'skip-cert-verify': params.get('allowInsecure', ['0'])[0] == '1',
                'sni': params.get('sni', [''])[0],
                'client-fingerprint': params.get('fp', ['']) or params.get('fingerprint', [''])[0]
            })
        elif security and security != 'none':
            logger.warning(f"Vless unsupported security: {security}")
            return None
        network = params.get('type', [''])[0]
        if network:
            node['network'] = network
            if network == 'ws':
                node.update({
                    'ws-path': params.get('path', ['/'])[0],
                    'ws-headers': {'Host': params['host'][0]} if params.get('host') else {}
                })
            elif network == 'grpc':
                node['grpc-service-name'] = params.get('serviceName', [''])[0]
        if 'flow' in params:
            node['flow'] = params['flow'][0]
        return ensure_node_name(node, 'vless')
    except Exception as e:
        logger.error(f"Error parsing vless: {str(e)}")
        return None

def parse_hysteria2(data: str) -> Optional[Dict[str, Any]]:
    """Parse hysteria2 protocol data."""
    try:
        parsed_url = urlparse(f"hysteria2://{data.strip()}")
        password, server, port = parsed_url.username, parsed_url.hostname, parsed_url.port or 443
        if not all([server, port, password]):
            logger.error(f"Invalid hysteria2: missing server, port, or password")
            return None
        params = parse_qs(parsed_url.query)
        node = {
            'name': unquote(parsed_url.fragment) or generate_node_name('hysteria2', server, port),
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'tls': True,
            'skip-cert-verify': params.get('insecure', ['0'])[0] == '1',
            'sni': params.get('sni', [''])[0],
            'alpn': params.get('alpn', [''])[0].split(',') if params.get('alpn') else [],
            'fast-open': params.get('fastopen', ['0'])[0] == '1',
            'client-fingerprint': params.get('fingerprint', [''])[0],
            'short-id': str(params.get('short-id', [''])[0]) if params.get('short-id') else ''
        }
        return ensure_node_name(node, 'hysteria2')
    except Exception as e:
        logger.error(f"Error parsing hysteria2: {str(e)}")
        return None

def parse_ssr(data: str) -> Optional[Dict[str, Any]]:
    """Parse ssr protocol data."""
    decoded = decode_base64(data.strip().replace('-', '+').replace('_', '/'))
    if not decoded:
        return None
    try:
        parts = decoded.split(':')
        if len(parts) < 6:
            logger.error(f"Invalid ssr: too few parts")
            return None
        server, port, protocol_type, method, obfs, password_part = parts[:6]
        password = decode_base64(password_part.split('/?')[0].replace('-', '+').replace('_', '/'))
        params = parse_qs(password_part.split('/?')[1]) if '/?' in password_part else {}
        name = decode_base64(params.get('remarks', [''])[0].replace('-', '+').replace('_', '/')) or generate_node_name('ssr', server, port)
        obfs_param = decode_base64(params.get('obfsparam', [''])[0].replace('-', '+').replace('_', '/')) or ''
        protocol_param = decode_base64(params.get('protoparam', [''])[0].replace('-', '+').replace('_', '/')) or ''
        if not all([server, port, method, password]):
            logger.error(f"Invalid ssr: missing server, port, method, or password")
            return None
        node = {
            'name': name,
            'type': 'ssr',
            'server': server,
            'port': int(port),
            'cipher': method or 'auto',
            'password': password,
            'protocol': protocol_type,
            'protocol-param': protocol_param,
            'obfs': obfs,
            'obfs-param': obfs_param
        }
        return ensure_node_name(node, 'ssr')
    except Exception as e:
        logger.error(f"Error parsing ssr: {str(e)}")
        return None

def parse_line_as_node(line: str) -> List[Dict[str, Any]]:
    """Parse a single line into one or more nodes."""
    line = line.strip()
    if not line:
        return []
    for protocol in CONFIG["SUPPORTED_PROTOCOLS"]:
        if line.startswith(f"{protocol}://"):
            parser = PROTOCOL_PARSERS.get(protocol)
            node = parser(line[len(protocol) + 3:]) if parser else None
            return [node] if node else []
    decoded = line
    for _ in range(5):
        decoded = decode_base64(decoded)
        if not decoded:
            break
        for protocol in CONFIG["SUPPORTED_PROTOCOLS"]:
            if decoded.startswith(f"{protocol}://"):
                return parse_line_as_node(decoded)
    return []

def parse_content(content: str) -> List[Dict[str, Any]]:
    """Parse content into a list of nodes."""
    content = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)
    try:
        data = yaml.safe_load(content)
        nodes = []
        if isinstance(data, dict):
            proxies = data.get('proxies', [data] if all(k in data for k in ['type', 'server', 'port']) else [])
            for proxy in proxies:
                if isinstance(proxy, dict) and all(k in proxy for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(proxy, proxy['type']))
                else:
                    logger.warning(f"Skipping invalid YAML proxy: {str(proxy)[:100]}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and all(k in item for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(item, item['type']))
                elif isinstance(item, str):
                    nodes.extend(parse_line_as_node(item))
                else:
                    logger.warning(f"Skipping invalid YAML item: {str(item)[:100]}")
        if nodes:
            logger.info(f"Parsed {len(nodes)} nodes from YAML")
            return nodes
    except yaml.YAMLError:
        pass
    try:
        data = json.loads(content)
        nodes = []
        if isinstance(data, dict):
            proxies = data.get('proxies', [data] if all(k in data for k in ['type', 'server', 'port']) else [])
            for proxy in proxies:
                if isinstance(proxy, dict) and all(k in proxy for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(proxy, proxy['type']))
                else:
                    logger.warning(f"Skipping invalid JSON proxy: {str(proxy)[:100]}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and all(k in item for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(item, item['type']))
                elif isinstance(item, str):
                    nodes.extend(parse_line_as_node(item))
                else:
                    logger.warning(f"Skipping invalid JSON item: {str(item)[:100]}")
        if nodes:
            logger.info(f"Parsed {len(nodes)} nodes from JSON")
            return nodes
    except json.JSONDecodeError:
        pass
    nodes = []
    for i, line in enumerate(content.splitlines(), 1):
        line_nodes = parse_line_as_node(line)
        if line_nodes:
            nodes.extend(line_nodes)
        elif line.strip():
            logger.warning(f"Could not parse line {i}: {line[:100]}")
    return nodes

def filter_nodes(proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter proxies based on validation rules and region filtering."""
    filtered_proxies = []
    seen_names = defaultdict(int)
    required_fields = {
        'vmess': ['server', 'port', 'uuid', 'alterId'],
        'trojan': ['server', 'port', 'password'],
        'ss': ['server', 'port', 'cipher', 'password'],
        'vless': ['server', 'port', 'uuid'],
        'hysteria2': ['server', 'port', 'password'],
        'ssr': ['server', 'port', 'cipher', 'password', 'protocol', 'obfs']
    }
    for i, proxy in enumerate(proxies, 1):
        if not isinstance(proxy, dict) or 'type' not in proxy:
            logger.warning(f"Skipping proxy {i}: malformed or missing 'type'")
            continue
        proxy_type = proxy['type']
        if proxy_type not in required_fields:
            logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): unsupported type '{proxy_type}'")
            continue
        missing = [f for f in required_fields[proxy_type] if f not in proxy]
        if missing:
            logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): missing {', '.join(missing)}")
            continue
        if proxy_type == 'vmess' and proxy.get('cipher', '').lower() not in CONFIG["VMESS_CIPHERS"]:
            logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): invalid cipher '{proxy.get('cipher')}'")
            continue
        if proxy_type == 'ss' and proxy.get('cipher', '').lower() == 'ss':
            logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): invalid cipher 'ss'")
            continue
        if proxy_type == 'vless':
            security = proxy.get('security')
            if security and security not in ['tls', 'none']:
                logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): unsupported security '{security}'")
                continue
        if proxy_type == 'ssr' and proxy.get('obfs') and not proxy.get('obfs-param', '').strip():
            logger.warning(f"Skipping proxy {i} ('{proxy.get('name', 'Unnamed')}'): missing obfs-param")
            continue
        if CONFIG["ENABLE_REGION_FILTERING"]:
            server = proxy.get('server') or proxy.get('host', '')
            name = proxy.get('name', '')
            if any(k.lower() in server.lower() or k.lower() in name.lower() for k in CONFIG["DOMESTIC_KEYWORDS"]):
                logger.info(f"Skipping proxy {i} ('{name}'): domestic node")
                continue
            if not any(k.lower() in server.lower() or k.lower() in name.lower() for k in CONFIG["KEEP_REGIONS"]):
                logger.info(f"Skipping proxy {i} ('{name}'): not in preferred regions")
                continue
        if 'short-id' in proxy:
            proxy['short-id'] = str(proxy['short-id'])
        if 'tls' in proxy:
            proxy['tls'] = proxy['tls'].lower() == 'true' if isinstance(proxy['tls'], str) else bool(proxy['tls'])
        filtered_proxies.append(proxy)
    final_proxies = []
    for proxy in filtered_proxies:
        name = proxy.get('name', 'unknown_node')
        count = seen_names[name]
        proxy['name'] = f"{name} #{count}" if count else name
        seen_names[name] += 1
        final_proxies.append(proxy)
    logger.info(f"Filtered to {len(final_proxies)} unique nodes")
    return final_proxies

def get_output_filename(url: str) -> str:
    """Generate output filename from URL."""
    parsed_url = urlparse(url)
    path_segments = [s for s in parsed_url.path.split('/') if s]
    if path_segments:
        base = path_segments[-1].split('.')[0]
        if "raw.githubusercontent.com" in parsed_url.hostname and len(path_segments) >= 3:
            user, repo = path_segments[:2]
            return re.sub(r'[^a-zA-Z0-9_.-]', '', f"{user}_{repo}_{base}.yaml")
        return re.sub(r'[^a-zA-Z0-9_.-]', '', base) + ".yaml"
    return re.sub(r'[^a-zA-Z0-9_.-]', '', parsed_url.hostname) + ".yaml"

def save_nodes_to_yaml(nodes: List[Dict[str, Any]], output_filepath: str):
    """Save nodes to a YAML file."""
    if not nodes:
        logger.info(f"No nodes to save to {output_filepath}")
        return
    for node in nodes:
        if 'short-id' in node:
            node['short-id'] = str(node['short-id'])
    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': nodes}, f, allow_unicode=True, indent=2, sort_keys=False)
        logger.info(f"Saved {len(nodes)} nodes to {output_filepath}")
    except Exception as e:
        logger.error(f"Error saving nodes to {output_filepath}: {str(e)}")

async def fetch_and_parse_nodes(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """Fetch and parse nodes from a URL."""
    content = await fetch_url(session, url)
    return parse_content(content) if content else []

async def main():
    """Main function to fetch, parse, filter, and save proxy nodes."""
    urls = [
        "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/ss.txt",
    ]
    all_nodes = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_and_parse_nodes(session, url) for url in urls]
        for nodes in await asyncio.gather(*tasks):
            all_nodes.extend(nodes)
    logger.info(f"Fetched {len(all_nodes)} nodes before filtering")
    filtered_nodes = filter_nodes(all_nodes)
    save_nodes_to_yaml(filtered_nodes, os.path.join('sc', 'all.yaml'))

if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())
