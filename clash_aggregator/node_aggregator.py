import yaml
import sys
import os
import base64
import re
import requests
import json
from urllib.parse import urlparse, unquote
import socket
import time # <--- 新增导入

# 定义靠近中国的地区关键词，用于初步筛选节点 (可以根据需要调整，但IP查询会更准)
# 增加常见缩写和中文名称，提高关键词匹配的准确性，以防IP查询失败。
REGION_KEYWORDS = ['hk', 'hong kong', 'tw', 'taiwan', 'sg', 'singapore', 'jp', 'japan', 'kr', 'korea', 'ru', 'russia', 'mo', 'macau', 'vn', 'vietnam', 'ph', 'philippines', 'th', 'thailand', 'my', 'malaysia', 'kp', 'north korea', 'mn', 'mongolia', 'cn', 'china']

# 定义允许的服务商关键词 (小写)，用于ASN/ISP过滤
# 例如：'amazon', 'microsoft', 'google', 'digitalocean', 'vultr', 'linode'
# 如果不希望过滤服务商，可以留空列表 []
ALLOWED_ISPS_ASNS = ['amazon', 'microsoft', 'google', 'digitalocean', 'vultr', 'linode', 'alibaba', 'tencent', 'huawei', 'cdn77', 'cloudflare', 'incapsula', 'fastly', 'akamai'] # 增加一些常见CDN/Proxy提供商

# 定义要排除的IP段或关键词 (例如：已知的不稳定或被滥用的服务商，可自行添加)
EXCLUDE_ISPS_ASNS = [] # 示例：['iran', 'russia telecom'] # 排除伊朗和俄罗斯的ISP

# IP查询API
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,regionName,city,isp,org,as,query"

# IP API 调用间隔 (秒)。ip-api.com 免费版限速通常是每分钟 45 次请求，所以这里设置为 1.5 秒确保不超限。
IP_API_COOLDOWN = 1.5 

# 源代码文件路径
SOURCES_FILE = 'sources.txt'


# --- 修改 get_ip_info 函数 ---
def get_ip_info(ip_address):
    """
    通过 ip-api.com 查询 IP 地址的地理位置、ISP 和 ASN 信息。
    注意：ip-api.com 有免费版限制，这里增加了延时处理。
    """
    try:
        # 尝试将域名解析为IP
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            try:
                ip_address = socket.gethostbyname(ip_address)
            except socket.gaierror:
                print(f"  Warning: Could not resolve hostname '{ip_address}' to IP address.", file=sys.stderr)
                return None

        # 增加延时以避免触发 IP API 的速率限制
        time.sleep(IP_API_COOLDOWN) 

        response = requests.get(IP_API_URL.format(ip=ip_address), timeout=5)
        response.raise_for_status() # 检查 HTTP 错误
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                'country_code': data.get('countryCode', '').lower(),
                'region_name': data.get('regionName', '').lower(), # State/Province
                'city': data.get('city', '').lower(),
                'isp': data.get('isp', '').lower(), # Internet Service Provider
                'org': data.get('org', '').lower(), # Organization name
                'asn': data.get('as', '').lower(),  # AS number and name (e.g., "AS16509 Amazon.com, Inc.")
                'ip': data.get('query')
            }
        else:
            print(f"  Warning: IP API query failed for {ip_address}: {data.get('message', 'Unknown error')}", file=sys.stderr)
            return None
    except requests.exceptions.RequestException as e:
        print(f"  Warning: IP API request failed for {ip_address}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: An unexpected error occurred during IP lookup for {ip_address}: {e}", file=sys.stderr)
    return None

# 定义其他不变的解析函数 (safe_load_yaml, decode_base64_url_safe, parse_vmess_link, parse_trojan_link, parse_ss_link, parse_vless_link, parse_hysteria2_link, parse_single_link_smart, fetch_and_parse_source, get_proxy_unique_key)
# 为了避免冗长，这里省略了这些函数的具体内容，它们与之前版本（即您之前收到的完整版本）完全相同。
# 请确保您使用之前版本中完整的这些函数代码。

# --- 其他解析函数（与之前版本相同，请勿省略） ---
def safe_load_yaml(content):
    """安全加载YAML内容，并处理可能的Clash配置键。"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                return data['proxies']
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
    else:
        return base_key


def main():
    all_proxies = {} # 使用字典存储代理，键为唯一标识符，值为代理配置
    
    if not os.path.exists(SOURCES_FILE):
        print(f"Error: {SOURCES_FILE} not found.", file=sys.stderr)
        sys.exit(1)

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"Found {len(sources)} sources in {SOURCES_FILE}.", file=sys.stderr)

    for source_url in sources:
        print(f"\nProcessing source: {source_url}", file=sys.stderr)
        proxies_from_source = fetch_and_parse_source(source_url)
        for proxy in proxies_from_source:
            if not isinstance(proxy, dict):
                print(f"  Warning: Skipping malformed proxy entry: {proxy}", file=sys.stderr)
                continue

            # 确保代理名称存在
            if 'name' not in proxy or not proxy['name']:
                proxy['name'] = f"{proxy.get('type', 'unknown')}-{proxy.get('server', 'unknown')[:8]}"

            unique_key = get_proxy_unique_key(proxy)
            if unique_key and unique_key not in all_proxies:
                all_proxies[unique_key] = proxy
            elif unique_key:
                # print(f"  Skipping duplicate proxy: {proxy.get('name')}", file=sys.stderr)
                pass # 已经存在，跳过

    final_proxies = list(all_proxies.values())
    print(f"\nTotal unique proxies collected: {len(final_proxies)}", file=sys.stderr)

    # --- 筛选逻辑 ---
    filtered_proxies = []
    for proxy in final_proxies:
        proxy_name_lower = proxy.get('name', '').lower()
        server_address = proxy.get('server')

        # 1. 基于名称的初步筛选（如果IP查询失败，这会是备用）
        name_match = False
        for keyword in REGION_KEYWORDS:
            if keyword in proxy_name_lower:
                name_match = True
                break
        
        # 2. IP 地理位置和 ASN/ISP 筛选
        ip_info = None
        if server_address:
            ip_info = get_ip_info(server_address)

        ip_match = False
        if ip_info:
            country_code = ip_info.get('country_code', '')
            isp = ip_info.get('isp', '')
            org = ip_info.get('org', '')
            asn = ip_info.get('asn', '') # AS number and name

            # 检查是否在允许的地区关键词中
            if country_code in REGION_KEYWORDS:
                ip_match = True
            else:
                # 检查 ASN/ISP 是否在允许列表中
                for allowed_term in ALLOWED_ISPS_ASNS:
                    if allowed_term in isp or allowed_term in org or allowed_term in asn:
                        ip_match = True
                        break
            
            # 检查是否在排除列表中
            for exclude_term in EXCLUDE_ISPS_ASNS:
                if exclude_term in isp or exclude_term in org or exclude_term in asn or exclude_term in country_code:
                    ip_match = False # 如果匹配到排除项，则强制不匹配
                    break
        
        # 综合判断：如果IP查询成功，以IP信息为准；否则，以名称匹配为准。
        # 如果IP查询失败，并且名称也没有匹配到关键词，则跳过。
        if ip_info: # IP查询成功
            if ip_match:
                filtered_proxies.append(proxy)
                # print(f"  Accepted (IP match): {proxy.get('name')} - {ip_info.get('country_code')}/{ip_info.get('isp')}", file=sys.stderr)
            # else:
                # print(f"  Rejected (IP no match): {proxy.get('name')} - {ip_info.get('country_code')}/{ip_info.get('isp')}", file=sys.stderr)
        elif name_match: # IP查询失败，但名称匹配
            filtered_proxies.append(proxy)
            # print(f"  Accepted (Name match, IP lookup failed): {proxy.get('name')}", file=sys.stderr)
        # else: # IP查询失败，名称也未匹配
            # print(f"  Rejected (No IP info, no name match): {proxy.get('name')}", file=sys.stderr)

    print(f"\nTotal filtered proxies: {len(filtered_proxies)}", file=sys.stderr)

    # 生成最终的 Clash YAML 配置
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': filtered_proxies,
        'proxy-groups': [
            {
                'name': 'Proxy',
                'type': 'select',
                'proxies': ['DIRECT'] + [p['name'] for p in filtered_proxies]
            },
            {
                'name': 'Direct',
                'type': 'select',
                'proxies': ['DIRECT']
            }
        ],
        'rules': [
            'MATCH,Proxy'
        ]
    }

    # 输出到标准输出
    print(yaml.dump(clash_config, allow_unicode=True, sort_keys=False))

if __name__ == "__main__":
    main()
