import yaml
import sys
import os
import base64
import re
import requests
import json
from urllib.parse import urlparse, unquote
import socket
import time

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

# 源代码文件路径 - 修正路径使其指向 'clash_aggregator' 目录内的 sources.txt
# os.path.dirname(__file__) 会获取当前脚本所在的目录
SOURCES_FILE = os.path.join(os.path.dirname(__file__), 'sources.txt')


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
                print(f"  Warning: 无法解析主机名 '{ip_address}' 到 IP 地址。", file=sys.stderr)
                return None

        # 增加延时以避免触发 IP API 的速率限制
        time.sleep(IP_API_COOLDOWN)

        response = requests.get(IP_API_URL.format(ip=ip_address), timeout=5)
        response.raise_for_status() # 检查 HTTP 错误
        data = response.json()

        if data.get('status') == 'success':
            return {
                'country_code': data.get('countryCode', '').lower(),
                'region_name': data.get('regionName', '').lower(), # 省份/地区
                'city': data.get('city', '').lower(),
                'isp': data.get('isp', '').lower(), # 互联网服务提供商
                'org': data.get('org', '').lower(), # 组织名称
                'asn': data.get('as', '').lower(),  # AS 号码和名称 (例如: "AS16509 Amazon.com, Inc.")
                'ip': data.get('query')
            }
        else:
            print(f"  Warning: IP API 查询 {ip_address} 失败：{data.get('message', '未知错误')}", file=sys.stderr)
            return None
    except requests.exceptions.RequestException as e:
        print(f"  Warning: IP API 请求 {ip_address} 失败：{e}", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: 查询 {ip_address} 的 IP 信息时发生意外错误：{e}", file=sys.stderr)
    return None

def safe_load_yaml(content):
    """安全加载YAML内容，并处理可能的Clash配置键。"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                return data['proxies']
            if 'proxy-providers' in data and isinstance(data['proxy-providers'], dict):
                print("Warning: YAML 中发现 'proxy-providers'，但未直接作为静态代理处理。", file=sys.stderr)
        return []
    except yaml.YAMLError as e:
        print(f"Warning: 无法解析 YAML 内容：{e}", file=sys.stderr)
        return []

def decode_base64_url_safe(s):
    """尝试以URL安全的方式解码Base64字符串。"""
    s = s.replace('-', '+').replace('_', '/')
    padding = len(s) % 4
    if padding == 1:
        raise ValueError("无效的 base64 字符串长度。")
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
        print(f"Warning: 无法解析 Vmess 链接 '{link[:50]}...': {e}", file=sys.stderr)
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
        print(f"Warning: 无法解析 Trojan 链接 '{link[:50]}...': {e}", file=sys.stderr)
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
            # 尝试解码 Base64 部分，例如 "ss://base64encoded_server_info#name"
            # 但有时 Base64 字符串后面直接跟 #name，所以要确保只解码服务器信息部分
            potential_base64_part = server_info_b64.split('/')[0] # 取 ? 或 # 之前的部分
            server_decoded = decode_base64_url_safe(potential_base64_part)
        except Exception:
            # 如果不是Base64编码，或者解码失败，就直接使用原始字符串
            server_decoded = server_info_b64

        # 分割 host 和 port
        if ':' in server_decoded:
            server_host, server_port_and_params = server_decoded.split(':', 1)
        else:
            # 如果没有端口，则链接格式不正确
            print(f"Warning: SS 链接 '{link[:50]}...' 缺少端口信息。", file=sys.stderr)
            return None

        # 提取纯数字端口，忽略后面的查询参数或路径
        server_port_str = server_port_and_params.split('?')[0].split('/')[0]
        # 再次确认，去除可能存在的非数字字符，这是预防性的，因为 int() 会失败
        server_port_str = ''.join(filter(str.isdigit, server_port_str))

        if not server_port_str:
            print(f"Warning: SS 链接 '{link[:50]}...' 清理后端口为空或非数字。", file=sys.stderr)
            return None

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

        # 进一步解析插件信息（如果存在）
        query_params = dict(re.findall(r"(\w+)=([^&]+)", server_port_and_params.split('?', 1)[1])) if '?' in server_port_and_params else {}
        if 'plugin' in query_params:
            proxy['plugin'] = query_params['plugin']
            plugin_opts = {}
            # 解析 v2ray-plugin 参数
            if proxy['plugin'] == 'v2ray-plugin':
                plugin_mode = query_params.get('mode', '')
                if 'websocket' in plugin_mode: # 检查是否包含 websocket
                    plugin_opts['mode'] = 'websocket'
                    # 其他websocket参数
                    if 'path' in query_params:
                        plugin_opts['path'] = query_params['path']
                    if 'host' in query_params:
                        plugin_opts['host'] = query_params['host']
                    if 'tls' in query_params and query_params['tls'] == 'tls':
                        plugin_opts['tls'] = True
                elif 'grpc' in plugin_mode:
                    plugin_opts['mode'] = 'grpc'
                    if 'serviceName' in query_params:
                        plugin_opts['serviceName'] = query_params['serviceName']
            # 解析 obfs-local 参数 (简单的示例，您可能需要更复杂的逻辑)
            elif proxy['plugin'] == 'obfs-local':
                plugin_opts['mode'] = query_params.get('mode', 'http') # 'http' or 'tls'
                if 'obfs-host' in query_params:
                    plugin_opts['host'] = query_params['obfs-host']

            if plugin_opts:
                proxy['plugin-opts'] = plugin_opts

        return proxy
    except Exception as e:
        print(f"Warning: 无法解析 SS 链接 '{link[:50]}...': {e}", file=sys.stderr)
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
        print(f"Warning: 无法解析 Vless 链接 '{link[:50]}...': {e}", file=sys.stderr)
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
        print(f"Warning: 无法解析 Hysteria2 链接 '{link[:50]}...': {e}", file=sys.stderr)
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
        print(f"Warning: 检测到 SSR 链接 '{link[:50]}...'。Clash 不原生支持 SSR，将跳过此链接。", file=sys.stderr)
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
            print(f"正在从 URL 获取: {source_path_or_url}", file=sys.stderr)
            response = requests.get(source_path_or_url, timeout=15)
            response.raise_for_status()
            content = response.text
        except requests.exceptions.RequestException as e:
            print(f"Error: 从 URL {source_path_or_url} 获取失败：{e}", file=sys.stderr)
            return []
    else:
        try:
            print(f"正在从文件读取: {source_path_or_url}", file=sys.stderr)
            with open(source_path_or_url, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: 文件 {source_path_or_url} 未找到。", file=sys.stderr)
            return []
        except Exception as e:
            print(f"Error: 读取文件 {source_path_or_url} 失败：{e}", file=sys.stderr)
            return []

    proxies = safe_load_yaml(content)
    if proxies:
        print(f"  已解析为 Clash YAML。找到 {len(proxies)} 个代理。", file=sys.stderr)
        return proxies

    try:
        decoded_content_b64 = decode_base64_url_safe(content)
        links = decoded_content_b64.splitlines()
        proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
        if proxies:
            print(f"  已解析为 Base64 编码链接。找到 {len(proxies)} 个代理。", file=sys.stderr)
            return proxies
    except Exception:
        pass

    links = content.splitlines()
    proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
    if proxies:
        print(f"  已解析为纯链接。找到 {len(proxies)} 个代理。", file=sys.stderr)
        return proxies

    print(f"Warning: 无法从 {source_path_or_url} 解析内容。内容起始：'{content[:100]}...'", file=sys.stderr)
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
        print(f"Error: {SOURCES_FILE} 文件未找到。", file=sys.stderr)
        sys.exit(1)

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"在 {SOURCES_FILE} 中找到 {len(sources)} 个源。", file=sys.stderr)

    for source_url in sources:
        print(f"\n正在处理源: {source_url}", file=sys.stderr)
        proxies_from_source = fetch_and_parse_source(source_url)
        for proxy in proxies_from_source:
            if not isinstance(proxy, dict):
                print(f"  Warning: 跳过格式错误的代理条目: {proxy}", file=sys.stderr)
                continue

            if 'name' not in proxy or not proxy['name']:
                proxy['name'] = f"{proxy.get('type', '未知')}-{proxy.get('server', '未知')[:8]}"

            unique_key = get_proxy_unique_key(proxy)
            if unique_key and unique_key not in all_proxies:
                all_proxies[unique_key] = proxy
            elif unique_key:
                pass

    final_proxies = list(all_proxies.values())
    print(f"\n收集到的总唯一代理数量: {len(final_proxies)}", file=sys.stderr)

    # --- 新增：基于名称的预筛选 (性能优化) ---
    # 这一步非常快，因为它不涉及任何网络请求，只处理名称字符串
    pre_filtered_proxies = []
    for proxy in final_proxies:
        proxy_name_lower = proxy.get('name', '').lower()
        
        name_match = False
        # 检查名称是否包含允许的地区关键词
        for keyword in REGION_KEYWORDS:
            if keyword in proxy_name_lower:
                name_match = True
                break
        
        # 检查名称是否包含允许的ISP/ASN关键词 (可以作为名称筛选的补充)
        for allowed_term in ALLOWED_ISPS_ASNS:
            if allowed_term in proxy_name_lower:
                name_match = True
                break

        # 如果名称中包含任何排除关键词，则直接跳过此代理
        should_exclude_by_name = False
        for exclude_term in EXCLUDE_ISPS_ASNS:
            if exclude_term in proxy_name_lower:
                should_exclude_by_name = True
                break
        
        # 只有当名称匹配 (或包含允许关键词) 且不在名称排除列表中时才进行 IP 查询
        if name_match and not should_exclude_by_name:
            pre_filtered_proxies.append(proxy)
        # else:
            # print(f"  预筛选跳过 (名称不匹配或在排除列表): {proxy.get('name')}", file=sys.stderr)


    print(f"名称预筛选后的代理数量: {len(pre_filtered_proxies)}", file=sys.stderr)

    # --- 对预筛选后的代理进行 IP 查询和最终筛选 ---
    final_filtered_proxies = []
    for proxy in pre_filtered_proxies: # 注意这里现在是遍历 pre_filtered_proxies，大大减少了 IP 查询的次数
        server_address = proxy.get('server')
        
        ip_info = None
        if server_address:
            # 耗时操作：IP 查询只对预筛选后的子集执行
            ip_info = get_ip_info(server_address) 

        ip_match = False
        if ip_info: # 如果成功获取到 IP 信息
            country_code = ip_info.get('country_code', '').lower()
            isp = ip_info.get('isp', '').lower()
            org = ip_info.get('org', '').lower()
            asn = ip_info.get('asn', '').lower()

            # 检查国家代码是否在允许的地区关键词中
            if country_code in REGION_KEYWORDS:
                ip_match = True
            else:
                # 检查 ISP/ASN 是否在允许列表中
                for allowed_term in ALLOWED_ISPS_ASNS:
                    if allowed_term in isp or allowed_term in org or allowed_term in asn:
                        ip_match = True
                        break

            # 检查是否在排除列表中 (IP 信息级别的排除)
            for exclude_term in EXCLUDE_ISPS_ASNS:
                if exclude_term in isp or exclude_term in org or exclude_term in asn or exclude_term in country_code:
                    ip_match = False # 如果匹配到排除项，则强制不匹配
                    break
        
        # 最终判断：
        # 如果 IP 查询成功并 IP 信息匹配 (即通过了 IP 地域/ISP 筛选)，则添加。
        # 或者，如果 IP 查询失败 (ip_info is None)，但该代理已经通过了名称预筛选，
        # 那么我们默认保留它，以防止因为临时的网络或 DNS 问题而错过节点。
        if ip_match or ip_info is None: 
            final_filtered_proxies.append(proxy)
        # else:
            # print(f"  最终筛选拒绝 (IP 信息不匹配): {proxy.get('name')}", file=sys.stderr)


    print(f"\n总过滤代理数量: {len(final_filtered_proxies)}", file=sys.stderr)

    # 生成最终的 Clash YAML 配置
    clash_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': final_filtered_proxies, # 注意这里使用 final_filtered_proxies
        'proxy-groups': [
            {
                'name': 'Proxy',
                'type': 'select',
                'proxies': ['DIRECT'] + [p['name'] for p in final_filtered_proxies]
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
