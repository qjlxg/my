#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 来源于https://github.com/xyfqzy

import asyncio
import aiohttp
import socket
import ssl
import time
import json
import base64
import re
import random
import logging
import os
import yaml
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

# --- 配置和设置 ---

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 节点来源列表
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml",
    "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/mh/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/mh/refs/heads/main/data/520.yaml"
]

# --- 数据类 ---

@dataclass
class NodeInfo:
    """从URL解析的节点信息。"""
    url: str
    protocol: str
    address: str
    port: int
    remarks: str = ""
    uuid: str = ""
    password: str = ""
    method: str = ""  # SS 加密方法
    security: str = ""  # VLESS 安全类型，例如 tls, reality
    network: str = "tcp"  # Vmess/Vless/Trojan 传输协议类型
    host: str = ""  # WS/H2 host 头
    path: str = ""  # WS/H2 path
    sni: str = ""  # TLS SNI
    flow: str = ""  # VLESS flow
    alter_id: int = 0  # Vmess alterId
    mux_enabled: bool = False  # Trojan mux
    obfs: str = ""  # SSR/SS 混淆插件
    obfs_param: str = ""  # SSR/SS 混淆参数
    protocol_param: str = ""  # SSR 协议参数
    obfs_hy2: str = ""  # Hysteria2 混淆
    obfs_password_hy2: str = ""  # Hysteria2 混淆密码
    alpn: List[str] = field(default_factory=list)
    insecure: bool = False  # Hysteria2/TLS 不安全跳过证书验证
    fast_open: bool = True  # Hysteria2 fast_open
    mptcp: bool = False  # Hysteria2 mptcp
    up_mbps: int = 0  # Hysteria2 上行带宽
    down_mbps: int = 0 # Hysteria2 下行带宽

# --- 节点解析器 (从 EnhancedNodeTester 独立出来) ---

class NodeParser:
    def __init__(self):
        pass

    def _decode_base64_urlsafe(self, s: str) -> str:
        """安全地解码 URL-safe Base64 字符串，处理填充。"""
        if not isinstance(s, str):
            return ""
        s = s.replace('-', '+').replace('_', '/')
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(s).decode('utf-8')
        except Exception:
            return ""

    def parse_node(self, url: str) -> Optional[NodeInfo]:
        """将节点 URL 解析为 NodeInfo 对象。"""
        try:
            if url.startswith('vmess://'):
                return self._parse_vmess(url)
            elif url.startswith('vless://'):
                return self._parse_vless(url)
            elif url.startswith('ss://'):
                return self._parse_shadowsocks(url)
            elif url.startswith('ssr://'):
                return self._parse_shadowsocksr(url)
            elif url.startswith('trojan://'):
                return self._parse_trojan(url)
            elif url.startswith('hysteria2://'):
                return self._parse_hysteria2(url)
            else:
                logger.debug(f"不支持的协议类型: {url[:30]}...")
                return None
        except Exception as e:
            logger.debug(f"解析节点 {url[:80]}... 失败: {e}")
            return None

    def _parse_vmess(self, url: str) -> Optional[NodeInfo]:
        """解析 VMess 链接。"""
        encoded = url[8:]
        decoded_json_str = self._decode_base64_urlsafe(encoded)
        if not decoded_json_str:
            return None
        
        data = json.loads(decoded_json_str)
        sni = data.get('sni') or data.get('host') or data.get('add')
        host = data.get('host') or data.get('add')

        return NodeInfo(
            url=url, protocol='vmess', address=data.get('add', ''), port=int(data.get('port', 0)),
            remarks=unquote(data.get('ps', '')), uuid=data.get('id', ''), alter_id=int(data.get('aid', 0)),
            security=data.get('tls', 'none'), network=data.get('net', 'tcp'), host=host,
            path=data.get('path', ''), sni=sni
        )

    def _parse_vless(self, url: str) -> Optional[NodeInfo]:
        """解析 VLESS 链接。"""
        parsed = urlparse(url)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        sni = params.get('sni', [params.get('host', [address])[0]])[0]
        
        return NodeInfo(
            url=url, protocol='vless', address=address, port=port,
            remarks=unquote(parsed.fragment or f"VLESS-{address}:{port}"), uuid=uuid,
            security=params.get('security', ['none'])[0], network=params.get('type', ['tcp'])[0],
            host=params.get('host', [''])[0], path=params.get('path', [''])[0],
            sni=sni, flow=params.get('flow', [''])[0]
        )

    def _parse_shadowsocks(self, url: str) -> Optional[NodeInfo]:
        """解析 Shadowsocks (SS) 链接。"""
        raw_data = url[5:]
        parts = raw_data.split('#', 1)
        encoded_part = parts[0]
        remarks = unquote(parts[1]) if len(parts) > 1 else ""

        decoded_auth_server = self._decode_base64_urlsafe(encoded_part)
        if not decoded_auth_server:
            return None

        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_auth_server)
        if not match:
            raise ValueError("SS 链接解码后格式不匹配")

        method, password, server, port = match.groups()

        return NodeInfo(
            url=url, protocol='ss', address=server, port=int(port),
            remarks=remarks or f"SS-{server}:{port}", method=method, password=password
        )

    def _parse_shadowsocksr(self, url: str) -> Optional[NodeInfo]:
        """解析 ShadowsocksR (SSR) 链接。"""
        encoded_part_with_fragment = url[6:]
        parts = encoded_part_with_fragment.split('#', 1)
        encoded_params = parts[0]
        remarks = unquote(parts[1]) if len(parts) > 1 else ""

        decoded_params = self._decode_base64_urlsafe(encoded_params)
        if not decoded_params:
            return None

        ssr_parts = decoded_params.split(':')
        if len(ssr_parts) < 6:
            raise ValueError("SSR 链接缺少组件")

        server = ssr_parts[0]
        port = int(ssr_parts[1])
        protocol = ssr_parts[2]
        method = ssr_parts[3]
        obfs = ssr_parts[4]
        password_and_query = ssr_parts[5]

        password = ""
        query_str = ""
        if '?' in password_and_query:
            password_encoded, query_str = password_and_query.split('?', 1)
            password = self._decode_base64_urlsafe(password_encoded)
        else:
            password = self._decode_base64_urlsafe(password_and_query)

        query_params = parse_qs(query_str)
        obfs_param = self._decode_base64_urlsafe(query_params.get('obfsparam', [''])[0])
        protocol_param = self._decode_base64_urlsafe(query_params.get('protoparam', [''])[0])

        return NodeInfo(
            url=url, protocol='ssr', address=server, port=int(port),
            remarks=remarks or f"SSR-{server}:{port}", password=password,
            method=method, obfs=obfs, obfs_param=obfs_param, protocol_param=protocol_param
        )

    def _parse_trojan(self, url: str) -> Optional[NodeInfo]:
        """解析 Trojan 链接。"""
        parsed = urlparse(url)
        password = parsed.username
        address = parsed.hostname
        port = parsed.port or 443
        params = parse_qs(parsed.query)
        sni = params.get('sni', [params.get('host', [address])[0]])[0]

        return NodeInfo(
            url=url, protocol='trojan', address=address, port=port,
            remarks=unquote(parsed.fragment or f"Trojan-{address}:{port}"),
            password=password, sni=sni, network=params.get('type', ['tcp'])[0],
            host=params.get('host', [''])[0], path=params.get('path', [''])[0],
            mux_enabled=params.get('mux', ['0'])[0] == '1'
        )

    def _parse_hysteria2(self, url: str) -> Optional[NodeInfo]:
        """解析 Hysteria2 链接。"""
        parsed = urlparse(url)
        password = parsed.username or ""
        address = parsed.hostname
        port = parsed.port

        if not address or not port:
            raise ValueError("Hysteria2 链接缺少地址或端口")
        
        params = parse_qs(parsed.query)
        sni = params.get('sni', [address])[0]
        
        return NodeInfo(
            url=url, protocol='hysteria2', address=address, port=port,
            remarks=unquote(parsed.fragment or f"Hysteria2-{address}:{port}"),
            password=password, obfs_hy2=params.get('obfs', [''])[0],
            obfs_password_hy2=params.get('obfsParam', [''])[0],
            alpn=params.get('alpn', ['h3']), insecure=params.get('insecure', ['0'])[0] == '1',
            fast_open=params.get('fastopen', ['1'])[0] == '1', mptcp=params.get('mptcp', ['0'])[0] == '1',
            up_mbps=int(params.get('up', ['0'])[0]), down_mbps=int(params.get('down', ['0'])[0]),
            sni=sni
        )

# --- 节点获取和 YAML 生成 ---

async def fetch_nodes_from_url(session: aiohttp.ClientSession, url: str) -> List[str]:
    """从给定的远程 URL 获取节点 URL，处理各种格式。"""
    try:
        logger.info(f"正在从以下地址获取节点: {url}")
        async with session.get(url, timeout=15) as response:
            response.raise_for_status() # 对 HTTP 错误 (4xx 或 5xx) 抛出异常
            content_type = response.headers.get('Content-Type', '')
            text_content = await response.text()

            # 处理 Base64 编码的内容
            if "text/plain" in content_type and not text_content.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')) and len(text_content) > 100:
                try:
                    decoded_content = base64.b64decode(text_content.strip()).decode('utf-8')
                    # 检查解码后的内容是否像 URL 列表或 YAML
                    if '\n' in decoded_content or decoded_content.strip().startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')):
                        text_content = decoded_content
                    elif decoded_content.strip().startswith(('proxies:', 'proxy-groups:', 'rules:')):
                         # 这是一个 Clash YAML
                        try:
                            config = yaml.safe_load(decoded_content)
                            if 'proxies' in config and isinstance(config['proxies'], list):
                                # 如果是 Clash YAML，转换为 URL 是复杂的且不保证。
                                # 目前，我们依赖于下面直接解析 Clash YAML 的逻辑。
                                pass 
                        except yaml.YAMLError:
                            pass # 不是有效的 YAML，继续
                except Exception as e:
                    logger.debug(f"从 {url} 解码 base64 失败: {e}")

            # 处理直接的节点列表 (每行一个 URL)
            if '\n' in text_content:
                lines = text_content.splitlines()
                nodes = []
                for line in lines:
                    line = line.strip()
                    if line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')):
                        nodes.append(line)
                if nodes: return nodes

            # 处理 Clash YAML (proxies 部分)
            if text_content.strip().startswith(('proxies:', 'proxy-groups:', 'rules:')) or "yaml" in content_type:
                try:
                    config = yaml.safe_load(text_content)
                    if 'proxies' in config and isinstance(config['proxies'], list):
                        clash_proxies = config['proxies']
                        nodes = []
                        # 尝试从代理字典中重建 URL
                        for proxy_dict in clash_proxies:
                            url = ""
                            if proxy_dict.get('type') == 'vmess':
                                # 这是一个简化；完整的 VMess URL 重建很复杂
                                vmess_config = {
                                    'add': proxy_dict.get('server'),
                                    'port': proxy_dict.get('port'),
                                    'id': proxy_dict.get('uuid'),
                                    'aid': proxy_dict.get('alterId', 0),
                                    'net': proxy_dict.get('network', 'tcp'),
                                    'ps': proxy_dict.get('name', ''),
                                    'tls': 'tls' if proxy_dict.get('tls') else 'none',
                                    'host': proxy_dict.get('ws-opts', {}).get('headers', {}).get('Host', '') if proxy_dict.get('network') == 'ws' else '',
                                    'path': proxy_dict.get('ws-opts', {}).get('path', '') if proxy_dict.get('network') == 'ws' else '',
                                    'sni': proxy_dict.get('servername', '')
                                }
                                url = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"
                            elif proxy_dict.get('type') == 'vless':
                                query_params = []
                                if proxy_dict.get('tls'): query_params.append('security=tls')
                                if proxy_dict.get('network'): query_params.append(f"type={proxy_dict.get('network')}")
                                if proxy_dict.get('network') == 'ws':
                                    if proxy_dict.get('ws-opts', {}).get('headers', {}).get('Host'):
                                        query_params.append(f"host={proxy_dict.get('ws-opts').get('headers').get('Host')}")
                                    if proxy_dict.get('ws-opts', {}).get('path'):
                                        query_params.append(f"path={proxy_dict.get('ws-opts').get('path')}")
                                elif proxy_dict.get('network') == 'grpc':
                                    if proxy_dict.get('grpc-opts', {}).get('serviceName'):
                                        query_params.append(f"serviceName={proxy_dict.get('grpc-opts').get('serviceName')}")
                                if proxy_dict.get('servername'): query_params.append(f"sni={proxy_dict.get('servername')}")
                                if proxy_dict.get('flow'): query_params.append(f"flow={proxy_dict.get('flow')}")
                                query_string = "&".join(query_params)
                                url = f"vless://{proxy_dict.get('uuid')}@{proxy_dict.get('server')}:{proxy_dict.get('port')}"
                                if query_string: url += f"?{query_string}"
                                if proxy_dict.get('name'): url += f"#{proxy_dict.get('name')}"
                            elif proxy_dict.get('type') == 'trojan':
                                query_params = []
                                if proxy_dict.get('servername'): query_params.append(f"sni={proxy_dict.get('servername')}")
                                if proxy_dict.get('network') == 'ws':
                                    if proxy_dict.get('ws-opts', {}).get('headers', {}).get('Host'):
                                        query_params.append(f"host={proxy_dict.get('ws-opts').get('headers').get('Host')}")
                                    if proxy_dict.get('ws-opts', {}).get('path'):
                                        query_params.append(f"path={proxy_dict.get('ws-opts').get('path')}")
                                elif proxy_dict.get('network') == 'grpc':
                                    if proxy_dict.get('grpc-opts', {}).get('serviceName'):
                                        query_params.append(f"serviceName={proxy_dict.get('grpc-opts').get('serviceName')}")
                                query_string = "&".join(query_params)
                                url = f"trojan://{proxy_dict.get('password')}@{proxy_dict.get('server')}:{proxy_dict.get('port')}"
                                if query_string: url += f"?{query_string}"
                                if proxy_dict.get('name'): url += f"#{proxy_dict.get('name')}"
                            elif proxy_dict.get('type') == 'ss':
                                auth_part = base64.b64encode(f"{proxy_dict.get('cipher')}:{proxy_dict.get('password')}".encode()).decode().rstrip('=')
                                server_port = f"{proxy_dict.get('server')}:{proxy_dict.get('port')}"
                                url = f"ss://{auth_part}@{server_port}#{proxy_dict.get('name', '')}"
                            elif proxy_dict.get('type') == 'hysteria2':
                                query_params = []
                                if proxy_dict.get('obfs'): query_params.append(f"obfs={proxy_dict.get('obfs')}")
                                if proxy_dict.get('obfs-password'): query_params.append(f"obfsParam={proxy_dict.get('obfs-password')}")
                                if proxy_dict.get('alpn'): query_params.append(f"alpn={','.join(proxy_dict.get('alpn'))}")
                                if proxy_dict.get('skip-cert-verify'): query_params.append('insecure=1')
                                if proxy_dict.get('servername'): query_params.append(f"sni={proxy_dict.get('servername')}")
                                # 如果 Clash YAML 中存在 Hysteria2 特定参数并希望重建，请在此处添加
                                query_string = "&".join(query_params)
                                url = f"hysteria2://{proxy_dict.get('password')}@{proxy_dict.get('server')}:{proxy_dict.get('port')}"
                                if query_string: url += f"?{query_string}"
                                if proxy_dict.get('name'): url += f"#{proxy_dict.get('name')}"
                            elif proxy_dict.get('type') == 'ssr':
                                # SSR URL 重建相当复杂，因为它涉及多层编码
                                # 这是一个占位符；需要完全遵守 SSR 规范
                                logger.warning(f"跳过从 Clash YAML 重建 SSR 代理: {proxy_dict.get('name')}")
                                url = "" # 如果没有完成复杂的重建，则不添加
                            if url:
                                nodes.append(url)
                        if nodes: return nodes
                except yaml.YAMLError as e:
                    logger.debug(f"解析 {url} 中的 YAML 失败: {e}")
            logger.warning(f"无法从 {url} 中提取节点。内容可能是不支持的格式或为空。")
            return []
    except aiohttp.ClientError as e:
        logger.error(f"获取 {url} 时发生 HTTP 错误: {e}")
        return []
    except asyncio.TimeoutError:
        logger.error(f"获取 {url} 超时")
        return []
    except Exception as e:
        logger.error(f"获取 {url} 时发生意外错误: {e}")
        return []

def to_clash_yaml_node(node_info: NodeInfo) -> Optional[Dict]:
    """将 NodeInfo 对象转换为 Clash YAML 兼容的字典。"""
    node = {
        "name": node_info.remarks if node_info.remarks else f"{node_info.protocol}-{node_info.address}:{node_info.port}",
        "server": node_info.address,
        "port": node_info.port,
    }
    if node_info.protocol == 'vmess':
        node["type"] = "vmess"
        node["uuid"] = node_info.uuid
        node["alterId"] = node_info.alter_id
        node["cipher"] = "auto"
        if node_info.network == "ws":
            node["network"] = "ws"
            ws_opts = {"path": node_info.path}
            if node_info.host:
                ws_opts["headers"] = {"Host": node_info.host}
            node["ws-opts"] = ws_opts
        if node_info.security == 'tls' or node_info.port == 443:
            node["tls"] = True
            if node_info.sni:
                node["servername"] = node_info.sni
    elif node_info.protocol == 'vless':
        node["type"] = "vless"
        node["uuid"] = node_info.uuid
        node["cipher"] = "auto"
        node["flow"] = node_info.flow
        if node_info.network == "ws":
            node["network"] = "ws"
            ws_opts = {"path": node_info.path}
            if node_info.host:
                ws_opts["headers"] = {"Host": node_info.host}
            node["ws-opts"] = ws_opts
        elif node_info.network == "grpc":
            node["network"] = "grpc"
            grpc_opts = {"serviceName": node_info.path.lstrip('/')}
            node["grpc-opts"] = grpc_opts
        if node_info.security in ['tls', 'reality']:
            node["tls"] = True
            if node_info.sni:
                node["servername"] = node_info.sni
    elif node_info.protocol == 'ss':
        node["type"] = "ss"
        node["password"] = node_info.password
        node["cipher"] = node_info.method
    elif node_info.protocol == 'trojan':
        node["type"] = "trojan"
        node["password"] = node_info.password
        node["tls"] = True
        if node_info.sni:
            node["servername"] = node_info.sni
        if node_info.network == "ws":
            node["network"] = "ws"
            ws_opts = {"path": node_info.path}
            if node_info.host:
                ws_opts["headers"] = {"Host": node_info.host}
            node["ws-opts"] = ws_opts
        elif node_info.network == "grpc":
            node["network"] = "grpc"
            grpc_opts = {"serviceName": node_info.path.lstrip('/')}
            node["grpc-opts"] = grpc_opts
    elif node_info.protocol == 'hysteria2':
        node["type"] = "hysteria2"
        node["password"] = node_info.password
        node["obfs"] = node_info.obfs_hy2
        node["obfs-password"] = node_info.obfs_password_hy2
        node["alpn"] = node_info.alpn
        node["udp"] = True
        node["fast-open"] = node_info.fast_open
        node["mptcp"] = node_info.mptcp
        node["skip-cert-verify"] = node_info.insecure
        if node_info.sni:
            node["servername"] = node_info.sni
    elif node_info.protocol == 'ssr':
        node["type"] = "ssr" # 需要 Clash.Meta 或特定的 Clash 构建版本
        node["password"] = node_info.password
        node["cipher"] = node_info.method
        node["protocol"] = node_info.protocol_param
        node["obfs"] = node_info.obfs
        node["obfs-param"] = node_info.obfs_param
    else:
        logger.warning(f"不支持将 {node_info.protocol} 协议转换为 Clash YAML: {node_info.remarks}")
        return None
    return node

def save_nodes_to_clash_yaml(node_infos: List[NodeInfo], filename: str = "sc/all.yaml"):
    """
    将 NodeInfo 对象列表保存到 Clash 兼容的 YAML 配置文件中。
    :param node_infos: NodeInfo 对象的列表。
    :param filename: 目标 YAML 文件路径。
    """
    if not node_infos:
        logger.warning("没有可用的节点数据保存到 YAML。")
        return

    clash_proxies = []
    for node_info in node_infos:
        clash_node = to_clash_yaml_node(node_info)
        if clash_node:
            clash_proxies.append(clash_node)

    if not clash_proxies:
        logger.warning("没有节点成功转换为 Clash YAML 格式。文件未生成。")
        return

    # 基本 Clash 配置框架
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "redir-port": 7892,
        "mixed-port": 7893,
        "allow-lan": False,
        "mode": "rule", # 设置默认模式为 rule
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "secret": "", # 您可能需要为外部控制器设置一个密钥
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:7893",
            "enhanced-mode": "redir-host",
            "default-nameserver": ["114.114.114.114", "223.5.5.5"],
            "nameserver": [
                "tls://dns.google/dns-query",
                "tls://1.1.1.1/dns-query"
            ],
            "fallback": [
                "tls://dns.alidns.com/dns-query",
                "tls://public.dns.wordpress.com/dns-query"
            ],
            "fallback-filter": {
                "geoip": True,
                "ipcidr": ["240.0.0.0/4"]
            }
        },
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🎯 直连"] + [node['name'] for node in clash_proxies]
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "proxies": [node['name'] for node in clash_proxies],
                "url": "http://www.google.com/generate_204",
                "interval": 300
            },
            {
                "name": "🎯 直连",
                "type": "direct"
            },
            {
                "name": "🛑 拒绝",
                "type": "reject"
            }
        ],
        "rules": [
            "PROCESS-NAME,clash,Proxy",
            "PROCESS-NAME,ShadowsocksX-NG,Proxy",
            "DOMAIN-SUFFIX,cn,🎯 直连",
            "DOMAIN-KEYWORD,cn,🎯 直连",
            "DOMAIN,speedtest.net,🎯 直连",
            "GEOIP,CN,🎯 直连",
            "MATCH,Proxy"
        ]
    }

    output_dir = os.path.dirname(filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, indent=2, sort_keys=False)
        logger.info(f"成功保存 {len(clash_proxies)} 个节点到 {filename}")
    except Exception as e:
        logger.error(f"保存 YAML 文件失败: {e}")

# --- 主执行 ---

async def main():
    logger.info("启动节点获取和转换过程 (无测试功能)...")

    all_raw_nodes: List[str] = []
    # 用于存储每个源及其获取到的节点列表
    fetched_nodes_by_source: List[Tuple[str, List[str]]] = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_nodes_from_url(session, source_url) for source_url in NODE_SOURCES]
        fetched_lists_raw = await asyncio.gather(*tasks) # 原始获取到的节点列表，与 NODE_SOURCES 顺序对应

        # 记录每个链接获取到的节点数量
        for i, source_url in enumerate(NODE_SOURCES):
            nodes_from_current_source = fetched_lists_raw[i]
            fetched_nodes_by_source.append((source_url, nodes_from_current_source))
            logger.info(f"从链接 '{source_url}' 获取到 {len(nodes_from_current_source)} 个节点。")
            all_raw_nodes.extend(nodes_from_current_source) # 聚合所有节点

    # 去重
    all_raw_nodes = list(dict.fromkeys(all_raw_nodes))
    logger.info(f"从所有来源共获取到 {len(all_raw_nodes)} 个唯一节点。")

    if not all_raw_nodes:
        logger.warning("没有获取到节点。退出。")
        return

    node_parser = NodeParser()
    all_parsed_nodes: List[NodeInfo] = []
    for raw_node_url in all_raw_nodes:
        node_info = node_parser.parse_node(raw_node_url)
        if node_info:
            all_parsed_nodes.append(node_info)
    
    logger.info(f"成功解析 {len(all_parsed_nodes)} 个节点。")

    if all_parsed_nodes:
        # 将所有成功解析的节点保存为 Clash YAML 文件，不再进行可用性筛选
        save_nodes_to_clash_yaml(all_parsed_nodes)
    else:
        logger.info("没有成功解析的节点来生成 Clash YAML 文件。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("脚本被用户中断。")
    except Exception as e:
        logger.critical(f"脚本执行过程中发生严重错误: {e}")
