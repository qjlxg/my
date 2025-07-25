import yaml
import sys
import os
import base64
import re
import json
import aiohttp
import asyncio
import socket
import time
import logging
import argparse
from urllib.parse import urlparse, unquote
from datetime import datetime, timedelta

# --- 配置日志 ---
LOG_FILE = 'clash_aggregator.log'

# 确保日志目录存在
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(LOG_FILE, encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# --- 全局配置 ---
REGION_KEYWORDS = [
    'hk', 'hong kong', 'tw', 'taiwan', 'sg', 'singapore', 'jp', 'japan', 'kr', 'korea',
    'ru', 'russia', 'mo', 'macau', 'vn', 'vietnam', 'ph', 'philippines', 'th', 'thailand',
    'my', 'malaysia', 'kp', 'north korea', 'mn', 'mongolia', 'cn', 'china'
]

ALLOWED_ASNS = {
    '16509': 'amazon', '14618': 'amazon',
    '8075': 'microsoft', '8068': 'microsoft',
    '15169': 'google',
    '14061': 'digitalocean',
    '20473': 'vultr',
    '63949': 'linode',
    '37963': 'alibaba', '45102': 'alibaba',
    '45090': 'tencent', '132203': 'tencent',
    '55900': 'huawei',
    '13335': 'cloudflare',
    '19551': 'incapsula',
    '54113': 'fastly',
    '714': 'akamai', '20940': 'akamai',
    '4809': 'china telecom', '4134': 'china telecom',
    '4837': 'china unicom', '9929': 'china unicom',
    '58453': 'china mobile', '9808': 'china mobile'
}

EXCLUDE_KEYWORDS = []

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,regionName,city,isp,org,as,query"
IP_CACHE_FILE = "ip_cache.json"
IP_API_CONCURRENCY = 10
IP_API_SEMAPHORE = asyncio.Semaphore(IP_API_CONCURRENCY)
IP_CACHE_EXPIRY_DAYS = 7  # 缓存过期时间（天）

SOURCES_FILE = os.path.join(os.path.dirname(__file__), 'sources.txt')

# 加载IP缓存并清理过期条目
IP_CACHE = {}
if os.path.exists(IP_CACHE_FILE):
    try:
        with open(IP_CACHE_FILE, 'r', encoding='utf-8') as f:
            cached_data = json.load(f)
        now = datetime.utcnow()
        for ip, info in cached_data.items():
            timestamp = info.get('timestamp')
            if timestamp:
                cache_time = datetime.fromisoformat(timestamp)
                if now - cache_time < timedelta(days=IP_CACHE_EXPIRY_DAYS):
                    IP_CACHE[ip] = info['data']
        logger.info(f"从 {IP_CACHE_FILE} 加载 {len(IP_CACHE)} 条有效IP缓存")
    except Exception as e:
        logger.warning(f"读取IP缓存文件失败：{e}")
        IP_CACHE = {}

def save_ip_cache():
    """保存IP缓存，包含时间戳"""
    try:
        cache_with_timestamp = {
            ip: {'data': info, 'timestamp': datetime.utcnow().isoformat()}
            for ip, info in IP_CACHE.items()
        }
        with open(IP_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_with_timestamp, f, ensure_ascii=False, indent=2)
        logger.info(f"IP缓存已保存到 {IP_CACHE_FILE}")
    except Exception as e:
        logger.error(f"写入IP缓存文件失败：{e}")

async def get_ip_info(ip_address, session):
    """异步查询IP信息，支持缓存和并发控制"""
    if ip_address in IP_CACHE:
        logger.debug(f"从缓存获取 {ip_address} 的IP信息")
        return IP_CACHE[ip_address]

    async with IP_API_SEMAPHORE:
        try:
            async with session.get(IP_API_URL.format(ip=ip_address), timeout=8) as response:
                response.raise_for_status()
                data = await response.json()
                if data.get('status') == 'success':
                    result = {
                        'country_code': data.get('countryCode', '').lower(),
                        'region_name': data.get('regionName', '').lower(),
                        'city': data.get('city', '').lower(),
                        'isp': data.get('isp', '').lower(),
                        'org': data.get('org', '').lower(),
                        'asn': data.get('as', '').lower(),
                        'ip': data.get('query')
                    }
                    IP_CACHE[ip_address] = result
                    return result
                else:
                    logger.warning(f"IP API 查询 {ip_address} 失败：{data.get('message', '未知错误')}")
                    return None
        except aiohttp.ClientError as e:
            logger.warning(f"IP API 请求 {ip_address} 失败（网络错误）：{e}")
        except asyncio.TimeoutError:
            logger.warning(f"IP API 请求 {ip_address} 超时")
        except Exception as e:
            logger.warning(f"查询 {ip_address} 的 IP 信息时发生意外错误：{e}")
        return None

def resolve_domain_to_ips(domain):
    """解析域名到IP地址列表"""
    if not isinstance(domain, str) or not domain:
        return []
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return [domain]
    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set([info[4][0] for info in addr_info]))
        logger.debug(f"解析域名 '{domain}' 为 IP: {ips}")
        return ips
    except socket.gaierror as e:
        logger.warning(f"无法解析域名 '{domain}' 到 IP 地址：{e}")
        return []
    except Exception as e:
        logger.warning(f"解析域名 '{domain}' 时发生意外错误：{e}")
        return []

def safe_load_yaml(content):
    """安全加载YAML内容"""
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                return data['proxies']
            if 'proxy-providers' in data:
                logger.info("发现 'proxy-providers'，但未直接处理")
        return []
    except yaml.YAMLError as e:
        logger.warning(f"无法解析 YAML 内容：{e}")
        return []

def decode_base64_url_safe(s):
    """安全解码Base64字符串"""
    if not isinstance(s, str):
        return None
    try:
        s = s.replace('-', '+').replace('_', '/')
        padding = len(s) % 4
        if padding == 1:
            raise ValueError("无效的 base64 字符串长度")
        elif padding == 2:
            s += '=='
        elif padding == 3:
            s += '='
        return base64.b64decode(s).decode('utf-8')
    except Exception as e:
        logger.debug(f"Base64 解码失败：{e}")
        return None

def parse_vmess_link(link):
    try:
        encoded_config = link[len("vmess://"):]
        decoded_config_str = decode_base64_url_safe(encoded_config)
        if not decoded_config_str:
            return None
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
        logger.warning(f"无法解析 Vmess 链接 '{link[:50]}...'：{e}")
        return None

def parse_trojan_link(link):
    try:
        parts = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts:
            return None
        password = parts.group(1)
        server = parts.group(2)
        port = int(parts.group(3))
        query_str = parts.group(4) if parts.group(4) else ""
        name_part = parts.group(5) if parts.group(5) else ""
        name = unquote(name_part[1:]) if name_part else f"trojan-{server[:8]}-{port}"
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
        logger.warning(f"无法解析 Trojan 链接 '{link[:50]}...'：{e}")
        return None

def parse_ss_link(link):
    try:
        parts = re.match(r"ss://(?:([^@]+)@)?([^#]+)(?:#(.+))?", link)
        if not parts:
            return None
        method_pass_b64 = parts.group(1)
        server_info = parts.group(2)
        name = unquote(parts.group(3)) if parts.group(3) else f"ss-{server_info[:8]}"
        method = 'auto'
        password = ''
        if method_pass_b64:
            decoded_mp = decode_base64_url_safe(method_pass_b64)
            if decoded_mp and ':' in decoded_mp:
                method, password = decoded_mp.split(':', 1)
            elif decoded_mp:
                password = decoded_mp
        server_decoded = server_info
        try:
            potential_base64_part = server_info.split('?')[0].split('/')[0]
            decoded_b64 = decode_base64_url_safe(potential_base64_part)
            if decoded_b64:
                server_decoded = decoded_b64
        except Exception:
            pass
        if ':' not in server_decoded:
            logger.warning(f"SS 链接 '{link[:50]}...' 缺少端口信息")
            return None
        server_host, server_port_and_params = server_decoded.split(':', 1)
        server_port_str = server_port_and_params.split('?')[0].split('/')[0]
        server_port_str = ''.join(filter(str.isdigit, server_port_str))
        if not server_port_str:
            logger.warning(f"SS 链接 '{link[:50]}...' 端口为空或非数字")
            return None
        port = int(server_port_str)
        proxy = {
            'name': f"ss-{server_host[:8]}-{port}",
            'type': 'ss',
            'server': server_host,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        query_params = dict(re.findall(r"(\w+)=([^&]+)", server_port_and_params.split('?', 1)[1])) if '?' in server_port_and_params else {}
        if 'plugin' in query_params:
            proxy['plugin'] = query_params['plugin']
            plugin_opts = {}
            if proxy['plugin'] == 'v2ray-plugin':
                plugin_mode = query_params.get('mode', '')
                if 'websocket' in plugin_mode:
                    plugin_opts['mode'] = 'websocket'
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
            elif proxy['plugin'] == 'obfs-local':
                plugin_opts['mode'] = query_params.get('mode', 'http')
                if 'obfs-host' in query_params:
                    plugin_opts['host'] = query_params['obfs-host']
            if plugin_opts:
                proxy['plugin-opts'] = plugin_opts
        return proxy
    except Exception as e:
        logger.warning(f"无法解析 SS 链接 '{link[:50]}...'：{e}")
        return None

def parse_vless_link(link):
    try:
        parts = re.match(r"vless://([a-f0-9-]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts:
            return None
        uuid = parts.group(1)
        server = parts.group(2)
        port = int(parts.group(3))
        query_str = parts.group(4) if parts.group(4) else ""
        name_part = parts.group(5) if parts.group(5) else ""
        name = unquote(name_part[1:]) if name_part else f"vless-{server[:8]}-{port}"
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
        logger.warning(f"无法解析 Vless 链接 '{link[:50]}...'：{e}")
        return None

def parse_hysteria2_link(link):
    try:
        parts = re.match(r"hysteria2://([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if not parts:
            return None
        server = parts.group(1)
        port = int(parts.group(2))
        query_str = parts.group(3) if parts.group(3) else ""
        name_part = parts.group(4) if parts.group(4) else ""
        name = unquote(name_part[1:]) if name_part else f"h2-{server[:8]}-{port}"
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
        logger.warning(f"无法解析 Hysteria2 链接 '{link[:50]}...'：{e}")
        return None

def parse_single_link_smart(link):
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
        logger.warning(f"检测到 SSR 链接 '{link[:50]}...'，Clash 不原生支持，跳过")
        return None
    else:
        decoded_content = decode_base64_url_safe(link)
        if decoded_content and decoded_content.startswith(('vmess://', 'trojan://', 'ss://', 'vless://', 'hysteria2://')):
            return parse_single_link_smart(decoded_content)
    return None

async def fetch_and_parse_source(source_path_or_url):
    content = ""
    if source_path_or_url.startswith(('http://', 'https://')):
        try:
            parsed_url = urlparse(source_path_or_url)
            if parsed_url.scheme not in ['http', 'https']:
                logger.error(f"无效的URL协议：{source_path_or_url}")
                return []
            logger.info(f"正在从 URL 获取: {source_path_or_url}")
            async with aiohttp.ClientSession() as session:
                async with session.get(source_path_or_url, timeout=20) as response:
                    response.raise_for_status()
                    content = await response.text()
        except aiohttp.ClientError as e:
            logger.error(f"从 URL {source_path_or_url} 获取失败（网络错误）：{e}")
            return []
        except asyncio.TimeoutError:
            logger.error(f"从 URL {source_path_or_url} 获取超时")
            return []
        except Exception as e:
            logger.error(f"从 URL {source_path_or_url} 获取时发生意外错误：{e}")
            return []
    else:
        try:
            logger.info(f"正在从文件读取: {source_path_or_url}")
            with open(source_path_or_url, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"文件 {source_path_or_url} 未找到")
            return []
        except Exception as e:
            logger.error(f"读取文件 {source_path_or_url} 失败：{e}")
            return []

    proxies = safe_load_yaml(content)
    if proxies:
        logger.info(f"已解析为 Clash YAML，找到 {len(proxies)} 个代理")
        return proxies

    decoded_content_b64 = decode_base64_url_safe(content)
    if decoded_content_b64:
        links = decoded_content_b64.splitlines()
        proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
        if proxies:
            logger.info(f"已解析为 Base64 编码链接，找到 {len(proxies)} 个代理")
            return proxies

    links = content.splitlines()
    proxies = [p for p in (parse_single_link_smart(link) for link in links) if p]
    if proxies:
        logger.info(f"已解析为纯链接，找到 {len(proxies)} 个代理")
        return proxies

    logger.warning(f"无法从 {source_path_or_url} 解析内容，内容起始：'{content[:100]}...'")
    return []

def get_proxy_unique_key(proxy):
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

def parse_args():
    parser = argparse.ArgumentParser(description="Clash Proxy Aggregator")
    parser.add_argument('--output', default=os.path.join(os.path.dirname(__file__), 'config.yaml'), help='输出 YAML 文件路径')
    parser.add_argument('--port', type=int, default=7890, help='Clash 代理端口')
    parser.add_argument('--socks-port', type=int, default=7891, help='Clash SOCKS 端口')
    parser.add_argument('--config-template', default=None, help='Clash 配置文件模板路径')
    parser.add_argument('--strict-ip-filter', action='store_true', help='严格IP筛选模式，IP查询失败的代理将被排除')
    return parser.parse_args()

async def main():
    args = parse_args()
    all_proxies = {}

    if not os.path.exists(SOURCES_FILE):
        logger.error(f"{SOURCES_FILE} 文件未找到")
        sys.exit(1)

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    logger.info(f"在 {SOURCES_FILE} 中找到 {len(sources)} 个源")

    # 收集所有代理
    for source_url in sources:
        logger.info(f"\n正在处理源: {source_url}")
        proxies_from_source = await fetch_and_parse_source(source_url)
        for proxy in proxies_from_source:
            if not isinstance(proxy, dict):
                logger.warning(f"跳过格式错误的代理条目: {proxy}")
                continue
            if 'name' not in proxy or not proxy['name']:
                proxy['name'] = f"{proxy.get('type', '未知')}-{proxy.get('server', '未知')[:8]}-{proxy.get('port', '')}"
            unique_key = get_proxy_unique_key(proxy)
            if unique_key and unique_key not in all_proxies:
                all_proxies[unique_key] = proxy

    initial_unique_proxies = list(all_proxies.values())
    logger.info(f"收集到的总唯一代理数量: {len(initial_unique_proxies)}")

    # 名称预筛选
    pre_filtered_proxies = []
    for proxy in initial_unique_proxies:
        proxy_name_lower = proxy.get('name', '').lower()
        name_passes_inclusion = False
        for keyword in REGION_KEYWORDS + list(ALLOWED_ASNS.values()):
            if keyword in proxy_name_lower:
                name_passes_inclusion = True
                break
        name_is_excluded = False
        for exclude_term in EXCLUDE_KEYWORDS:
            if exclude_term in proxy_name_lower:
                name_is_excluded = True
                break
        if name_passes_inclusion and not name_is_excluded:
            pre_filtered_proxies.append(proxy)
        else:
            logger.debug(f"名称预筛选跳过: {proxy.get('name')}")

    logger.info(f"名称预筛选后的代理数量: {len(pre_filtered_proxies)}")

    # 异步IP查询
    ips_to_query = set()
    proxy_server_to_ips = {}
    for proxy in pre_filtered_proxies:
        server_address = proxy.get('server')
        if server_address:
            ips = resolve_domain_to_ips(server_address)
            proxy_server_to_ips[server_address] = ips
            ips_to_query.update(ips)

    logger.info(f"需要查询IP信息的唯一IP地址数量: {len(ips_to_query)}")

    async with aiohttp.ClientSession() as session:
        ip_info_tasks = [get_ip_info(ip, session) for ip in ips_to_query]
        ip_infos = await asyncio.gather(*ip_info_tasks, return_exceptions=True)

    # 保存IP缓存
    save_ip_cache()

    # 最终筛选
    final_filtered_proxies = []
    for proxy in pre_filtered_proxies:
        server_address = proxy.get('server')
        if not server_address:
            if not args.strict_ip_filter:
                final_filtered_proxies.append(proxy)
            continue

        resolved_ips = proxy_server_to_ips.get(server_address, [])
        if not resolved_ips:
            if not args.strict_ip_filter:
                final_filtered_proxies.append(proxy)
            continue

        ip_matched = False
        for ip in resolved_ips:
            ip_info = IP_CACHE.get(ip)
            if not ip_info:
                continue
            country_code = ip_info.get('country_code', '').lower()
            isp = ip_info.get('isp', '').lower()
            org = ip_info.get('org', '').lower()
            asn = ip_info.get('asn', '').lower()
            asn_number = re.match(r"AS(\d+)", asn)
            asn_number = asn_number.group(1) if asn_number else ""

            is_excluded_by_ip = False
            for exclude_term in EXCLUDE_KEYWORDS:
                if exclude_term in country_code or exclude_term in isp or exclude_term in org or exclude_term in asn:
                    is_excluded_by_ip = True
                    break

            if is_excluded_by_ip:
                logger.debug(f"IP筛选跳过 (在排除列表): {proxy.get('name')} -> {ip} ({country_code}/{isp}/{asn})")
                continue

            if country_code in REGION_KEYWORDS or (asn_number and asn_number in ALLOWED_ASNS):
                ip_matched = True
                break
            for allowed_asn_name in ALLOWED_ASNS.values():
                if allowed_asn_name in isp or allowed_asn_name in org or allowed_asn_name in asn:
                    ip_matched = True
                    break
            if ip_matched:
                break

        if ip_matched or (not args.strict_ip_filter and not resolved_ips):
            final_filtered_proxies.append(proxy)
        else:
            logger.debug(f"IP筛选跳过 (IP信息不匹配): {proxy.get('name')}")

    logger.info(f"总过滤代理数量: {len(final_filtered_proxies)}")

    # 生成或加载Clash配置
    clash_config = {
        'port': args.port,
        'socks-port': args.socks_port,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': final_filtered_proxies,
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
        'rules': ['MATCH,Proxy']
    }

    if args.config_template and os.path.exists(args.config_template):
        try:
            with open(args.config_template, 'r', encoding='utf-8') as f:
                template = yaml.safe_load(f)
            template['proxies'] = final_filtered_proxies
            proxy_group_updated = False
            for group in template.get('proxy-groups', []):
                if group.get('name') == 'Proxy' and group.get('type') == 'select':
                    group['proxies'] = ['DIRECT'] + [p['name'] for p in final_filtered_proxies]
                    proxy_group_updated = True
                    break
            if not proxy_group_updated:
                template.setdefault('proxy-groups', []).append({
                    'name': 'Proxy',
                    'type': 'select',
                    'proxies': ['DIRECT'] + [p['name'] for p in final_filtered_proxies]
                })
            clash_config = template
            logger.info(f"已加载配置文件模板: {args.config_template}")
        except Exception as e:
            logger.warning(f"加载配置文件模板失败：{e}，使用默认配置")

    # 保存配置
    try:
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(args.output, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
        logger.info(f"Clash 配置已保存到 {args.output}")
    except Exception as e:
        logger.error(f"保存配置文件到 {args.output} 失败：{e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
