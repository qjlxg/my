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
                # 对于proxy-providers，通常需要进一步解析其url来获取实际节点
                # 这里为了简化，我们只处理内嵌的静态代理列表
                # 实际中，proxy-providers通常是动态订阅，需要单独下载
                print("Warning: 'proxy-providers' found in YAML, but not directly processed as static proxies.", file=sys.stderr)
        return [] # 如果不是Clash配置或无法解析，返回空列表
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse YAML content: {e}", file=sys.stderr)
        return []

def decode_base64_url_safe(s):
    """尝试以URL安全的方式解码Base64字符串。"""
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding == 1:
        # Invalid base64 string, cannot pad.
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
            'cipher': config.get('scy', 'auto'), # scy for cipher in some configs
            'tls': config.get('tls') == 'tls',
            'skip-cert-verify': config.get('scy', '') == 'true' or config.get('skip-cert-verify', False), # scy also for skip-cert-verify
            'network': config.get('net', 'tcp'),
            'udp': True # 默认开启 UDP
        }
        # WebSocket settings
        if proxy['network'] == 'ws':
            proxy['ws-path'] = config.get('path', '/')
            proxy['ws-headers'] = {'Host': config.get('host')} if config.get('host') else {}
        # gRPC settings
        if proxy['network'] == 'grpc':
            proxy['grpc-service-name'] = config.get('path', '')
            proxy['grpc-multi-mode'] = config.get('mode', '') == 'gun' # 'gun' mode for multi-mode

        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Vmess link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_trojan_link(link):
    """解析 Trojan 链接为 Clash 代理格式。"""
    try:
        # trojan://password@server:port?params#name
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
            'tls': True, # Trojan 默认开启 TLS
            'skip-cert-verify': query_params.get('allowInsecure', '0') == '1' or query_params.get('insecure', '0') == '1',
            'udp': True # 默认开启 UDP
        }
        if 'alpn' in query_params:
            proxy['alpn'] = [a.strip() for a in query_params['alpn'].split(',')]
        if 'peer' in query_params: # sni for trojan-go
            proxy['sni'] = query_params['peer']
        elif 'sni' in query_params: # common sni param
            proxy['sni'] = query_params['sni']
        
        # WebSocket settings for Trojan-Go
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
        # ss://[method:password@]base64_encoded_info#name
        parts = re.match(r"ss://(?:([^@]+)@)?([^#]+)(?:#(.+))?", link)
        if not parts: return None

        method_pass_b64 = parts.group(1) # method:password if available and b64 encoded
        server_info_b64 = parts.group(2) # server:port or b64 encoded server:port
        name = unquote(parts.group(3)) if parts.group(3) else f"ss-{server_info_b64[:8]}"

        method = 'auto'
        password = ''

        # Decrypt method:password if base64 encoded
        if method_pass_b64:
            decoded_mp = decode_base64_url_safe(method_pass_b64)
            if ':' in decoded_mp:
                method, password = decoded_mp.split(':', 1)
            else: # Sometimes just password is encoded
                password = decoded_mp
        
        # Decode server info part
        # This part is tricky as sometimes it's plain server:port, sometimes base64 encoded
        server_decoded = server_info_b64
        try:
            server_decoded = decode_base64_url_safe(server_info_b64.split('/')[0])
        except Exception:
            pass # Not base64 encoded, assume plain text

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
        # vless://uuid@server:port?params#name
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
        if 'fp' in query_params: # flow control / fingerprint
            proxy['flow'] = query_params['fp'] # flow is for xtls
        if 'alpn' in query_params:
            proxy['alpn'] = [a.strip() for a in query_params['alpn'].split(',')]

        return proxy
    except Exception as e:
        print(f"Warning: Failed to parse Vless link '{link[:50]}...': {e}", file=sys.stderr)
    return None

def parse_hysteria2_link(link):
    """解析 Hysteria2 链接为 Clash 代理格式。"""
    try:
        # hysteria2://server:port?params#name
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
            'password': query_params.get('auth', ''), # Hysteria2 的密码通常是 'auth'
            'obfs': query_params.get('obfs', 'none'),
            'obfs-password': query_params.get('obfsParam', ''),
            'tls': query_params.get('tls', '1') == '1', # 默认开启 TLS
            'skip-cert-verify': query_params.get('insecure', '0') == '1',
            'udp': True, # Hysteria2 默认支持 UDP
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
    link = unquote(link.strip()) # 统一处理百分号编码和空白

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
    # 可以添加其他协议支持
    else:
        # 如果不是标准链接格式，尝试 Base64 解码，再解析为链接
        try:
            decoded_content = decode_base64_url_safe(link)
            # 尝试再次解析为链接
            if decoded_content.startswith(('vmess://', 'trojan://', 'ss://', 'vless://', 'hysteria2://')):
                return parse_single_link_smart(decoded_content)
        except Exception:
            pass # 不是Base64编码，或者解码后也不是标准链接

    # print(f"Warning: Unrecognized or unparsable link format: '{link[:100]}...'", file=sys.stderr)
    return None

def fetch_and_parse_source(source_path_or_url):
    """从文件或 URL 读取内容，并尝试智能解析多种格式。"""
    content = ""
    if source_path_or_url.startswith(('http://', 'https://')):
        try:
            print(f"Fetching from URL: {source_path_or_url}", file=sys.stderr)
            response = requests.get(source_path_or_url, timeout=15)
            response.raise_for_status() # 检查 HTTP 错误
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

    # 尝试多种解析方式
    # 1. 尝试解析为 Clash YAML 格式 (包括完整的config和纯proxies列表)
    proxies = safe_load_yaml(content)
    if proxies:
        print(f"  Parsed as Clash YAML. Found {len(proxies)} proxies.", file=sys.stderr)
        return proxies
    
    # 2. 尝试解析为 Base64 编码的链接列表
    try:
        decoded_content_b64 = decode_base64_url_safe(content)
        links = decoded_content_b64.splitlines()
        proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
        if proxies:
            print(f"  Parsed as Base64 encoded links. Found {len(proxies)} proxies.", file=sys.stderr)
            return proxies
    except Exception:
        pass # Not base64, or decoding failed

    # 3. 尝试解析为纯文本链接列表
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
        return None # 缺少基本信息

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
    
    return base_key # 兜底

# --- 主程序逻辑 ---
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python node_aggregator.py <input_path_or_url_1> [input_path_or_url_2] ...", file=sys.stderr)
        sys.exit(1)

    all_proxies = {} # 使用字典进行去重
    total_parsed_count = 0

    for source in sys.argv[1:]:
        print(f"\n--- Processing source: {source} ---", file=sys.stderr)
        parsed_proxies = fetch_and_parse_source(source)
        total_parsed_count += len(parsed_proxies)

        for proxy in parsed_proxies:
            if not isinstance(proxy, dict) or not proxy.get('type'):
                print(f"  Warning: Skipping malformed proxy entry: {proxy}", file=sys.stderr)
                continue

            # 提取服务器地址用于地区过滤
            server_address = proxy.get('server')
            if not server_address:
                print(f"  Warning: Skipping proxy '{proxy.get('name', 'Unnamed')}' (type: {proxy.get('type')}) as it has no 'server' key.", file=sys.stderr)
                continue
            
            # 地区过滤：根据服务器地址或节点名称
            matched_region = False
            for keyword in REGION_KEYWORDS:
                if keyword.lower() in server_address.lower():
                    matched_region = True
                    break
            # 也检查节点名称（remark/name）
            proxy_name = proxy.get('remark') or proxy.get('name', '')
            if not matched_region: 
                for keyword in REGION_KEYWORDS:
                    if keyword.lower() in proxy_name.lower():
                        matched_region = True
                        break

            if matched_region:
                proxy_key = get_proxy_unique_key(proxy)
                if proxy_key and proxy_key not in all_proxies:
                    # 确保 'tls' 字段是布尔值 (部分链接解析器可能提供字符串)
                    if 'tls' in proxy and isinstance(proxy['tls'], str):
                        proxy['tls'] = proxy['tls'].lower() == 'true'
                    all_proxies[proxy_key] = proxy
                # else:
                #     print(f"  Info: Skipping duplicate proxy: {proxy.get('name', 'Unnamed')}", file=sys.stderr)
            else:
                print(f"  Info: Skipping proxy '{proxy.get('name', 'Unnamed')}' (server/host: {server_address}) as it does not match close-to-China regions.", file=sys.stderr)

    final_proxies_list = list(all_proxies.values())
    
    output_file = 'filtered_nodes_for_speedtest.yaml' # 输出到这个文件，给测速工具用
    
    # 构建输出配置：只包含过滤后的代理，并确保是标准的Clash YAML结构
    output_config = {'proxies': final_proxies_list}
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"\n--- Aggregation Summary ---", file=sys.stderr)
    print(f"Total proxies parsed from all sources: {total_parsed_count}", file=sys.stderr)
    print(f"Unique, region-filtered proxies saved to '{output_file}': {len(final_proxies_list)}", file=sys.stderr)
