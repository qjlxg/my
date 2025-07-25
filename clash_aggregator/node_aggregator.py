import yaml
import sys
import os
import base64
import re
import requests
import json
from urllib.parse import urlparse, unquote
import socket # 用于IP解析

# 定义靠近中国的地区关键词，用于初步筛选节点 (可以根据需要调整，但IP查询会更准)
REGION_KEYWORDS = ['hk', 'tw', 'sg', 'jp', 'kr', 'ru', 'mo', 'vn', 'ph', 'th', 'my', 'kp', 'mn']

# 定义允许的服务商关键词 (小写)，用于ASN/ISP过滤
# 例如：'amazon', 'microsoft', 'google', 'digitalocean', 'vultr', 'linode'
# 如果不希望过滤服务商，可以留空列表 []
ALLOWED_ISPS_ASNS = ['amazon', 'microsoft', 'google', 'digitalocean', 'vultr', 'linode', 'alibaba', 'tencent', 'huawei']

# 定义要排除的IP段或关键词 (例如：已知的不稳定或被滥用的服务商，可自行添加)
# EXCLUDE_ISPS_ASNS = ['alibaba', 'tencent'] # 示例：排除阿里云和腾讯云
EXCLUDE_ISPS_ASNS = []

# IP查询API
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,regionName,city,isp,org,as,query"


# --- 新增函数：查询IP信息 ---
def get_ip_info(ip_address):
    """
    通过 ip-api.com 查询 IP 地址的地理位置、ISP 和 ASN 信息。
    注意：ip-api.com 有免费版限制，可能会触发限速。
    """
    try:
        # 尝试将域名解析为IP
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            try:
                ip_address = socket.gethostbyname(ip_address)
            except socket.gaierror:
                print(f"  Warning: Could not resolve hostname '{ip_address}' to IP address.", file=sys.stderr)
                return None

        response = requests.get(IP_API_URL.format(ip=ip_address), timeout=5)
        response.raise_for_status() # 检查 HTTP 错误
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                'country_code': data.get('countryCode'),
                'region_name': data.get('regionName'),
                'city': data.get('city'),
                'isp': data.get('isp'), # Internet Service Provider
                'org': data.get('org'), # Organization name
                'asn': data.get('as'),  # AS number and name (e.g., "AS16509 Amazon.com, Inc.")
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

# 定义其他不变的解析函数 (vmess, trojan, ss, vless, hysteria2, safe_load_yaml, decode_base64_url_safe, parse_single_link_smart)
# 为了避免冗长，这里省略了这些函数的具体内容，它们与之前版本完全相同。
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
    
    return base_key

# --- 主程序逻辑 ---
if __name__ == '__main__':
    # 尝试从命令行参数获取 sources 文件路径，如果没有则使用默认值
    if len(sys.argv) > 1:
        custom_sources_file = sys.argv[1]
        print(f"Using custom sources file: {custom_sources_file}", file=sys.stderr)
        read_sources_file = custom_sources_file
    else:
        # 获取当前脚本的目录
        script_dir = os.path.dirname(os.path.abspath(__file__))
        read_sources_file = os.path.join(script_dir, SOURCES_FILE)
        print(f"Using default sources file: {read_sources_file}", file=sys.stderr)

    # 读取来源链接列表
    try:
        with open(read_sources_file, 'r', encoding='utf-8') as f:
            # 过滤掉空行和注释行
            source_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"Error: Sources file '{read_sources_file}' not found. Please create it in the same directory as the script and add your subscription URLs.", file=sys.stderr)
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

            # 获取服务器地址（可能是域名或IP）
            server_address_or_domain = proxy.get('server')
            if not server_address_or_domain:
                print(f"  Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy.get('type')}) as it has no 'server' key.", file=sys.stderr)
                continue

            # --- 核心过滤逻辑修改 ---
            # 优先使用IP信息进行过滤
            ip_info = get_ip_info(server_address_or_domain)
            
            # 初始化过滤状态
            passes_region_filter = False
            passes_isp_asn_filter = False

            if ip_info:
                # 地区过滤
                country_code = ip_info.get('country_code', '').lower()
                region_name = ip_info.get('region_name', '').lower()
                city = ip_info.get('city', '').lower()
                
                # 检查国家代码或区域名称是否在允许的关键词中
                if country_code in [kw.lower() for kw in REGION_KEYWORDS] or \
                   any(kw.lower() in region_name for kw in REGION_KEYWORDS) or \
                   any(kw.lower() in city for kw in REGION_KEYWORDS):
                    passes_region_filter = True
                
                # ISP/ASN 过滤
                isp_name = ip_info.get('isp', '').lower()
                org_name = ip_info.get('org', '').lower()
                asn_name = ip_info.get('asn', '').lower() # AS12345 example.com, Inc.

                # 检查是否在允许的服务商列表中 (如果 ALLOWED_ISPS_ASNS 不为空)
                if ALLOWED_ISPS_ASNS:
                    if any(allowed_isp.lower() in isp_name for allowed_isp in ALLOWED_ISPS_ASNS) or \
                       any(allowed_isp.lower() in org_name for allowed_isp in ALLOWED_ISPS_ASNS) or \
                       any(allowed_isp.lower() in asn_name for allowed_isp in ALLOWED_ISPS_ASNS):
                        passes_isp_asn_filter = True
                    else:
                        passes_isp_asn_filter = False # 不在允许列表中
                else:
                    passes_isp_asn_filter = True # 如果ALLOW_ISPS_ASNS为空，表示不进行此过滤

                # 检查是否在排除的服务商列表中 (如果 EXCLUDE_ISPS_ASNS 不为空)
                if EXCLUDE_ISPS_ASNS:
                    if any(exclude_isp.lower() in isp_name for exclude_isp in EXCLUDE_ISPS_ASNS) or \
                       any(exclude_isp.lower() in org_name for exclude_isp in EXCLUDE_ISPS_ASNS) or \
                       any(exclude_isp.lower() in asn_name for exclude_isp in EXCLUDE_ISPS_ASNS):
                        print(f"  Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' ({server_address_or_domain}) due to excluded ISP/ASN: {isp_name}/{asn_name}", file=sys.stderr)
                        continue # 直接跳过
            else:
                # 如果IP查询失败，退回到旧的基于名称/服务器地址的关键词过滤
                print(f"  Info: IP lookup failed for {server_address_or_domain}. Falling back to keyword matching for region.", file=sys.stderr)
                # 仍然尝试使用旧的 REGION_KEYWORDS 逻辑
                if any(kw.lower() in server_address_or_domain.lower() for kw in REGION_KEYWORDS) or \
                   any(kw.lower() in (proxy.get('remark') or proxy.get('name', '')).lower() for kw in REGION_KEYWORDS):
                    passes_region_filter = True
                passes_isp_asn_filter = True # 如果IP查询失败，不进行ISP/ASN过滤

            # 最终判断是否通过所有过滤
            if passes_region_filter and passes_isp_asn_filter:
                proxy_key = get_proxy_unique_key(proxy)
                if proxy_key and proxy_key not in all_proxies:
                    if 'tls' in proxy and isinstance(proxy['tls'], str):
                        proxy['tls'] = proxy['tls'].lower() == 'true'
                    all_proxies[proxy_key] = proxy
            else:
                # 打印更详细的跳过原因
                if not passes_region_filter:
                    print(f"  Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' ({server_address_or_domain}) as it does not match close-to-China regions based on IP info or keyword.", file=sys.stderr)
                # ISP/ASN的跳过在上面已处理

    final_proxies_list = list(all_proxies.values())
    
    output_file = 'filtered_nodes_for_speedtest.yaml'
    
    output_config = {'proxies': final_proxies_list}
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"\n--- Aggregation Summary ---", file=sys.stderr)
    print(f"Total proxies parsed from all sources: {total_parsed_count}", file=sys.stderr)
    print(f"Unique, region-filtered proxies saved to '{output_file}': {len(final_proxies_list)}", file=sys.stderr)
