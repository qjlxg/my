import yaml
import sys
import os
import base64
import re
import requests
import json
from urllib.parse import urlparse, unquote

# 定义靠近中国的地区关键词，用于初步筛选节点
REGION_KEYWORDS = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru']

# --- 核心修改点：不再硬编码 NODE_SOURCES，而是从文件读取 ---
# 源代码文件路径
SOURCES_FILE = 'sources.txt'
# --- 核心修改点结束 ---


def safe_load_yaml(content):
    """安全加载YAML内容，并处理可能的Clash配置键。"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # 检查是否是完整的Clash配置，如果是，提取proxies
            if 'proxies' in data and isinstance(data['proxies'], list):
                return data['proxies']
            # 检查是否有proxy-providers，尝试提取
            if 'proxy-providers' in data and isinstance(data['proxy-providers'], dict):
                print("Warning: 'proxy-providers' found in YAML, but not directly processed as static proxies.", file=sys.stderr)
        return []
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse YAML content: {e}", file=sys.stderr)
        return []

def decode_base64_url_safe(s):
    """尝试以URL安全的方式解码Base64字符串。"""
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding == 1:
        raise ValueError("Invalid base64 string length.")
    elif padding == 2:
        s += '=='
    elif padding == 3:
        s += '='
    return base64.b64decode(s).decode('utf-8')

def parse_vmess_link(link):
    """解析 Vmess 链接为 Clash 代理格式。"""
    try:
        encoded_config = link[len("vmess://"):]
        decoded_config_str = decode_base64_url_safe(encoded_config)
        config = json.loads(decoded_config_str)

        proxy = {
            'name': config.get('ps', f"vmess-{config.get('add', '')[:8]}"),
            'type': 'vmess',
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': config.get('scy', 'auto'),
            'tls': config.get('tls') == 'tls',
            'skip-cert-verify': config.get('scy', '') == 'true' or config.get('skip-cert-verify', False),
            'network': config.get('net', 'tcp'),
            'udp': True
        }
        if proxy['network'] == 'ws':
            proxy['ws-path'] = config.get('path', '/')
            proxy['ws-headers'] = {'Host': config.get('host')} if config.get('host') else {}
        if proxy['network'] == 'grpc':
            proxy['grpc-service-name'] = config.get('path', '')
            proxy['grpc-multi-mode'] = config.get('mode', '') == 'gun'

        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Vmess link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_trojan_link(link):
    """解析 Trojan 链接为 Clash 代理格式。"""
    try:
        parts = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts: return None

        password = parts.group(1)
        server = parts.group(2)
        port = int(parts.group(3))
        query_str = parts.group(4) if parts.group(4) else ""
        name_part = parts.group(5) if parts.group(5) else ""

        name = unquote(name_part[1:]) if name_part else f"trojan-{server[:8]}"
        
        query_params = dict(re.findall(r"(\w+)=([^&]+)", query_str[1:])) if query_str else {}

        proxy = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'tls': True,
            'skip-cert-verify': query_params.get('allowInsecure', '0') == '1' or query_params.get('insecure', '0') == '1',
            'udp': True
        }
        if 'alpn' in query_params:
            proxy['alpn'] = [a.strip() for a in query_params['alpn'].split(',')]
        if 'peer' in query_params:
            proxy['sni'] = query_params['peer']
        elif 'sni' in query_params:
            proxy['sni'] = query_params['sni']
        
        if query_params.get('type') == 'ws':
            proxy['network'] = 'ws'
            proxy['ws-path'] = query_params.get('path', '/')
            proxy['ws-headers'] = {'Host': query_params.get('host') or server}
        
        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Trojan link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_ss_link(link):
    """解析 Shadowsocks (SS) 链接为 Clash 代理格式。"""
    try:
        parts = re.match(r"ss://(?:([^@]+)@)?([^#]+)(?:#(.+))?", link)
        if not parts: return None

        method_pass_b64 = parts.group(1)
        server_info_b64 = parts.group(2)
        name = unquote(parts.group(3)) if parts.group(3) else f"ss-{server_info_b64[:8]}"

        method = 'auto'
        password = ''

        if method_pass_b64:
            decoded_mp = decode_base64_url_safe(method_pass_b64)
            if ':' in decoded_mp:
                method, password = decoded_mp.split(':', 1)
            else:
                password = decoded_mp
        
        server_decoded = server_info_b64
        try:
            server_decoded = decode_base64_url_safe(server_info_b64.split('/')[0])
        except Exception:
            pass

        server_host, server_port_str = server_decoded.split(':', 1)
        port = int(server_port_str)

        proxy = {
            'name': name,
            'type': 'ss',
            'server': server_host,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse SS link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_vless_link(link):
    """解析 Vless 链接为 Clash 代理格式。"""
    try:
        parts = re.match(r"vless://([a-f0-9-]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts: return None

        uuid = parts.group(1)
        server = parts.group(2)
        port = int(parts.group(3))
        query_str = parts.group(4) if parts.group(4) else ""
        name_part = parts.group(5) if parts.group(5) else ""

        name = unquote(name_part[1:]) if name_part else f"vless-{server[:8]}"
        query_params = dict(re.findall(r"(\w+)=([^&]+)", query_str[1:])) if query_str else {}

        proxy = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'tls': query_params.get('security') == 'tls',
            'skip-cert-verify': query_params.get('allowInsecure', '0') == '1' or query_params.get('insecure', '0') == '1',
            'network': query_params.get('type', 'tcp'),
            'udp': True
        }
        if proxy['network'] == 'ws':
            proxy['ws-path'] = query_params.get('path', '/')
            proxy['ws-headers'] = {'Host': query_params.get('host') or server}
        if proxy['network'] == 'grpc':
            proxy['grpc-service-name'] = query_params.get('serviceName', '')
            proxy['grpc-multi-mode'] = query_params.get('mode', '') == 'gun'
        if 'fp' in query_params:
            proxy['flow'] = query_params['fp']
        if 'alpn' in query_params:
            proxy['alpn'] = [a.strip() for a in query_params['alpn'].split(',')]

        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Vless link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_hysteria2_link(link):
    """解析 Hysteria2 链接为 Clash 代理格式。"""
    try:
        parts = re.match(r"hysteria2://([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts: return None

        server = parts.group(1)
        port = int(parts.group(2))
        query_str = parts.group(3) if parts.group(3) else ""
        name_part = parts.group(4) if parts.group(4) else ""

        name = unquote(name_part[1:]) if name_part else f"h2-{server[:8]}"
        query_params = dict(re.findall(r"(\w+)=([^&]+)", query_str[1:])) if query_str else {}

        proxy = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': query_params.get('auth', ''),
            'obfs': query_params.get('obfs', 'none'),
            'obfs-password': query_params.get('obfsParam', ''),
            'tls': query_params.get('tls', '1') == '1',
            'skip-cert-verify': query_params.get('insecure', '0') == '1',
            'udp': True,
            'fast-open': query_params.get('fastopen', '0') == '1'
        }
        if 'alpn' in query_params:
            proxy['alpn'] = [a.strip() for a in query_params['alpn'].split(',')]
        if 'sni' in query_params:
            proxy['sni'] = query_params['sni']

        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Hysteria2 link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_single_link_smart(link):
    """智能解析单个代理链接。"""
    link = unquote(link.strip())

    if link.startswith("vmess://"):
        return parse_vmess_link(link)
    elif link.startswith("trojan://"):
        return parse_trojan_link(link)
    elif link.startswith("ss://"):
        return parse_ss_link(link)
    elif link.startswith("vless://"):
        return parse_vless_link(link)
    elif link.startswith("hysteria2://"):
        return parse_hysteria2_link(link)
    elif link.startswith("ssr://"):
        print(f"Warning: SSR link '{link[:50]}...' detected. Clash does not natively support SSR and it will be skipped.", file=sys.stderr)
        return None
    else:
        try:
            decoded_content = decode_base64_url_safe(link)
            if decoded_content.startswith(('vmess://', 'trojan://', 'ss://', 'vless://', 'hysteria2://')):
                return parse_single_link_smart(decoded_content)
        except Exception:
            pass
    return None

def fetch_and_parse_source(source_path_or_url):
    """从文件或 URL 读取内容，并尝试智能解析多种格式。"""
    content = ""
    if source_path_or_url.startswith(('http://', 'https://')):
        try:
            print(f"Fetching from URL: {source_path_or_url}", file=sys.stderr)
            response = requests.get(source_path_or_url, timeout=15)
            response.raise_for_status()
            content = response.text
        except requests.exceptions.RequestException as e:
            print(f"Error fetching URL {source_path_or_url}: {e}", file=sys.stderr)
            return []
    else:
        try:
            print(f"Reading from file: {source_path_or_url}", file=sys.stderr)
            with open(source_path_or_url, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: File not found at {source_path_or_url}", file=sys.stderr)
            return []
        except Exception as e:
            print(f"Error reading file {source_path_or_url}: {e}", file=sys.stderr)
            return []

    proxies = safe_load_yaml(content)
    if proxies:
        print(f"  Parsed as Clash YAML. Found {len(proxies)} proxies.", file=sys.stderr)
        return proxies
    
    try:
        decoded_content_b64 = decode_base64_url_safe(content)
        links = decoded_content_b64.splitlines()
        proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
        if proxies:
            print(f"  Parsed as Base64 encoded links. Found {len(proxies)} proxies.", file=sys.stderr)
            return proxies
    except Exception:
        pass

    links = content.splitlines()
    proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
    if proxies:
        print(f"  Parsed as plain links. Found {len(proxies)} proxies.", file=sys.stderr)
        return proxies

    print(f"Warning: Could not parse content from {source_path_or_url}. Content start: '{content[:100]}...'", file=sys.stderr)
    return []

def get_proxy_unique_key(proxy):
    """生成代理的唯一键用于去重。"""
    if not isinstance(proxy, dict) or 'type' not in proxy:
        return None
    
    p_type = proxy['type']
    p_server = proxy.get('server')
    p_port = proxy.get('port')

    if not p_server or not p_port:
        return None

    base_key = f"{p_type}_{p_server}:{p_port}"

    if p_type == 'vmess':
        return f"{base_key}_{proxy.get('uuid', '')}"
    elif p_type == 'trojan':
        return f"{base_key}_{proxy.get('password', '')}"
    elif p_type == 'ss':
        return f"{base_key}_{proxy.get('cipher', '')}_{proxy.get('password', '')}"
    elif p_type == 'vless':
        return f"{base_key}_{proxy.get('uuid', '')}"
    elif p_type == 'hysteria2':
         return f"{base_key}_{proxy.get('password', '')}"
    
    return base_key

# --- 主程序逻辑 ---
if __name__ == '__main__':
    # 尝试从命令行参数获取 sources 文件路径，如果没有则使用默认值
    if len(sys.argv) > 1:
        custom_sources_file = sys.argv[1]
        print(f"Using custom sources file: {custom_sources_file}", file=sys.stderr)
        read_sources_file = custom_sources_file
    else:
        print(f"Using default sources file: {SOURCES_FILE}", file=sys.stderr)
        read_sources_file = SOURCES_FILE

    # 读取来源链接列表
    try:
        with open(read_sources_file, 'r', encoding='utf-8') as f:
            source_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"Error: Sources file '{read_sources_file}' not found. Please create it and add your subscription URLs.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading sources file '{read_sources_file}': {e}", file=sys.stderr)
        sys.exit(1)

    if not source_urls:
        print("Warning: No source URLs found in the sources file. Exiting.", file=sys.stderr)
        sys.exit(0) # 正常退出，但没有节点处理

    all_proxies = {}
    total_parsed_count = 0

    for source in source_urls:
        print(f"\n--- Processing source: {source} ---", file=sys.stderr)
        parsed_proxies = fetch_and_parse_source(source)
        total_parsed_count += len(parsed_proxies)

        for proxy in parsed_proxies:
            if not isinstance(proxy, dict) or not proxy.get('type'):
                print(f"  Warning: Skipping malformed proxy entry: {proxy}", file=sys.stderr)
                continue

            server_address = proxy.get('server')
            if not server_address:
                print(f"  Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy.get('type')}) as it has no 'server' key.", file=sys.stderr)
                continue
            
            matched_region = False
            for keyword in REGION_KEYWORDS:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            proxy_name = proxy.get('remark') or proxy.get('name', '')
            if not matched_region: 
                for keyword in REGION_KEYWORDS:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            if matched_region:
                proxy_key = get_proxy_unique_key(proxy)
                if proxy_key and proxy_key not in all_proxies:
                    if 'tls' in proxy and isinstance(proxy['tls'], str):
                        proxy['tls'] = proxy['tls'].lower() == 'true'
                    all_proxies[proxy_key] = proxy
            else:
                print(f"  Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' (server/host: {server_address}) as it does not match close-to-China regions.", file=sys.stderr)

    final_proxies_list = list(all_proxies.values())
    
    output_file = 'filtered_nodes_for_speedtest.yaml'
    
    output_config = {'proxies': final_proxies_list}
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"\n--- Aggregation Summary ---", file=sys.stderr)
    print(f"Total proxies parsed from all sources: {total_parsed_count}", file=sys.stderr)
    print(f"Unique, region-filtered proxies saved to '{output_file}': {len(final_proxies_list)}", file=sys.stderr)
