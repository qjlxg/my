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

# --- Configuration and Setup ---

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 节点来源列表
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml",
    "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt", # 这个链接之前返回了404错误
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml" # 这个链接之前返回了404错误
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

@dataclass
class TestResult:
    """节点测试结果。"""
    node_info: NodeInfo
    basic_connectivity: bool = False # 基础连接性
    ssl_handshake: bool = False       # SSL/TLS 握手
    protocol_test: bool = False       # 协议参数验证
    http_proxy_test: bool = False     # 是否理论上支持 HTTP 代理
    latency_ms: float = 0.0           # 延迟（毫秒）
    error_message: str = ""           # 错误信息
    china_score: int = 0              # 中国可用性评分
    is_china_usable: bool = False     # 是否在中国可用
    suggestion: str = ""              # 建议

# --- 核心测试器类 ---

class EnhancedNodeTester:
    def __init__(self, timeout=20, max_concurrent_tasks=30, china_mode=True):
        """
        初始化增强节点测试器。

        :param timeout: 单个连接/操作的超时时间（秒）。已从10秒增加到20秒。
        :param max_concurrent_tasks: 最大并发测试任务数。已从50减少到30。
        :param china_mode: 是否使用针对中国大陆的测试目标。
        """
        self.timeout = timeout
        self.max_concurrent_tasks = max_concurrent_tasks
        self.china_mode = china_mode
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.sem = asyncio.Semaphore(self.max_concurrent_tasks) # 限制并发异步任务

        # 针对中国大陆的测试目标
        self.china_test_targets = [
            "https://www.google.com/generate_204", # Google 无内容响应，适合探测
            "https://www.facebook.com/favicon.ico",
            "https://www.twitter.com/favicon.ico",
            "https://www.instagram.com/favicon.ico",
            "https://www.reddit.com/favicon.ico",
        ]
        
        # 全球范围的测试目标
        self.global_test_targets = [
            "https://www.cloudflare.com/favicon.ico",
            "https://www.amazon.com/favicon.ico",
            "https://www.microsoft.com/favicon.ico",
            "https://www.apple.com/favicon.ico",
            "https://www.netflix.com/favicon.ico"
        ]
        
        # 评分权重
        self.score_weights = {
            'connectivity': 0.2, # 连接性权重
            'latency': 0.2,      # 延迟权重
            'ssl_handshake': 0.2, # SSL握手权重
            'protocol_param': 0.1, # 协议参数权重
            'http_proxy': 0.2,   # HTTP代理能力权重
            'port_commonality': 0.1 # 端口常用性权重
        }

    async def __aenter__(self):
        """异步上下文管理器入口，用于 aiohttp 会话。"""
        self.http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'},
            connector=aiohttp.TCPConnector(ssl=False) # 我们执行显式SSL检查，因此这里不验证
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口，用于关闭 aiohttp 会话。"""
        if self.http_session:
            await self.http_session.close()

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

    async def _test_basic_connectivity_async(self, node_info: NodeInfo) -> Tuple[bool, float, str]:
        """异步基础 TCP 连接性测试。"""
        try:
            start_time = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node_info.address, node_info.port),
                timeout=self.timeout
            )
            latency = (time.monotonic() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
            return True, latency, ""
        except asyncio.TimeoutError:
            return False, 0, "连接超时"
        except ConnectionRefusedError:
            return False, 0, "连接被拒绝"
        except socket.gaierror:
            return False, 0, "DNS 解析失败"
        except Exception as e:
            return False, 0, f"连接错误: {str(e)}"

    async def _test_ssl_handshake_async(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """异步 SSL/TLS 握手测试。"""
        # 判断是否需要进行 TLS 检查
        requires_tls_check = (
            (node_info.protocol in ['vmess', 'vless', 'trojan'] and node_info.security == 'tls') or
            node_info.protocol == 'hysteria2' or
            node_info.port == 443
        )
        if not requires_tls_check:
            return True, "不适用 (未配置 TLS 或非 443 端口)"

        try:
            context = ssl.create_default_context()
            if node_info.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
            
            target_sni = node_info.sni if node_info.sni else node_info.address
            # 对于 SS/SSR 协议，即使端口是 443，如果它们本身不支持 SNI 或 TLS，我们也不强制要求 SNI
            if not target_sni and node_info.protocol not in ['ss', 'ssr']: 
                 # 如果需要 TLS 但缺少 SNI，则标记为失败
                return False, "SSL: 协议需要 SNI 但未提供"

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node_info.address, node_info.port, ssl=context, server_hostname=target_sni),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            return True, f"SSL 握手成功，SNI: {target_sni}"
        except ssl.SSLError as e:
            return False, f"SSL 错误: {str(e)}"
        except asyncio.TimeoutError:
            return False, "SSL 握手超时"
        except ConnectionRefusedError:
            return False, "SSL 连接被拒绝"
        except Exception as e:
            return False, f"SSL 测试失败: {str(e)}"

    async def _test_http_proxy_async(self, result: TestResult) -> Tuple[bool, float, str]:
        """
        模拟 HTTP 代理测试。此函数目前假设如果 TCP/SSL/协议验证通过，
        节点理论上能够代理 HTTP 流量。真正的 HTTP 代理测试将涉及本地代理
        或协议特定的 HTTP 隧道，这超出了简单节点检查器的范围。
        """
        node_info = result.node_info # 从 TestResult 中获取 NodeInfo

        # 如果节点涉及 TLS/WebSocket/gRPC，并且 SSL 握手成功，
        # 我们认为它能够承载 HTTP 流量。
        # 对于 SS/SSR，如果基本连接和参数正常，我们也假设如此。
        # 这是一个简化处理。
        if (node_info.protocol in ['vmess', 'vless', 'trojan', 'hysteria2'] and result.ssl_handshake) or \
           (node_info.protocol in ['ss', 'ssr'] and result.basic_connectivity):
            return True, 0.0, "通过协议/TLS 握手假定 HTTP 代理能力"
        else:
            return False, 0.0, "协议不直接适合简单 HTTP 代理测试或前置阶段失败"

    def _test_protocol_specific(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """协议特定参数验证。"""
        try:
            if node_info.protocol == 'vmess':
                return self._validate_vmess_params(node_info)
            elif node_info.protocol == 'vless':
                return self._validate_vless_params(node_info)
            elif node_info.protocol == 'trojan':
                return self._validate_trojan_params(node_info)
            elif node_info.protocol == 'ss':
                return self._validate_ss_params(node_info)
            elif node_info.protocol == 'ssr':
                return self._validate_ssr_params(node_info)
            elif node_info.protocol == 'hysteria2':
                return self._validate_hysteria2_params(node_info)
            else:
                return False, "未知协议"
        except Exception as e:
            return False, f"协议验证失败: {str(e)}"

    def _validate_vmess_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 VMess 协议参数。"""
        if not all([node_info.uuid, node_info.address, node_info.port]): return False, "VMess: 缺少必需字段"
        # VMess TLS 安全可以是 'none' 或 'tls'。如果是 'tls'，SNI 很重要但不是规范强制要求。
        if node_info.security == 'tls' and not node_info.sni and node_info.network in ['ws', 'h2', 'grpc']:
            return True, "VMess 带 TLS 但 Web 传输缺少 SNI。可能仍然有效。"
        return True, "VMess 参数正常"

    def _validate_vless_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 VLESS 协议参数。"""
        if not all([node_info.uuid, node_info.address, node_info.port]): return False, "VLESS: 缺少必需字段"
        if node_info.security in ['tls', 'reality'] and not node_info.sni:
            return False, "VLESS 带 TLS/Reality: 强烈建议并通常需要 SNI。"
        if node_info.network in ['ws', 'grpc'] and not node_info.path:
            return False, f"VLESS 带 {node_info.network}: 通常需要 Path。"
        return True, "VLESS 参数正常"

    def _validate_trojan_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 Trojan 协议参数。"""
        if not all([node_info.password, node_info.address, node_info.port]): return False, "Trojan: 缺少必需字段"
        if not node_info.sni:
            return False, "Trojan: 强烈建议使用 SNI。"
        return True, "Trojan 参数正常"

    def _validate_ss_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 Shadowsocks (SS) 协议参数。"""
        if not all([node_info.method, node_info.password, node_info.address, node_info.port]): return False, "SS: 缺少必需字段"
        valid_methods = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305', 'aes-256-cfb', 'aes-128-cfb', 'none']
        if node_info.method not in valid_methods:
            return False, f"SS: 不支持的方法: {node_info.method}"
        return True, "SS 参数正常"
    
    def _validate_ssr_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 ShadowsocksR (SSR) 协议参数。"""
        if not all([node_info.address, node_info.port, node_info.method, node_info.password, node_info.protocol_param, node_info.obfs]):
            return False, "SSR: 缺少必需字段"
        return True, "SSR 参数正常"

    def _validate_hysteria2_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """验证 Hysteria2 协议参数。"""
        if not all([node_info.address, node_info.port, node_info.password]): return False, "Hysteria2: 缺少必需字段"
        if not node_info.sni:
            return False, "Hysteria2: 强烈建议使用 SNI。"
        if not node_info.alpn:
            return False, "Hysteria2: 需要 ALPN。"
        return True, "Hysteria2 参数正常"

    def _calculate_china_score(self, result: TestResult) -> int:
        """计算中国可用性评分。"""
        score = 0
        if result.basic_connectivity: score += self.score_weights['connectivity'] * 100
        if result.latency_ms > 0:
            if result.latency_ms < 100: score += self.score_weights['latency'] * 100
            elif result.latency_ms < 200: score += self.score_weights['latency'] * 80
            elif result.latency_ms < 500: score += self.score_weights['latency'] * 60
            elif result.latency_ms < 1000: score += self.score_weights['latency'] * 40
            else: score += self.score_weights['latency'] * 20
        if result.ssl_handshake: score += self.score_weights['ssl_handshake'] * 100
        if result.protocol_test: score += self.score_weights['protocol_param'] * 100
        if result.http_proxy_test: score += self.score_weights['http_proxy'] * 100 # 对于可用性很重要
        if result.node_info.port in [80, 443, 8080, 8443, 2053, 2083, 2087, 2096, 8388, 8389]:
            score += self.score_weights['port_commonality'] * 100
        
        # 协议特定加分
        if result.node_info.protocol in ['trojan', 'vless', 'hysteria2']: score += 5
        elif result.node_info.protocol == 'vmess' and result.node_info.network == 'ws' and result.node_info.security == 'tls': score += 5

        return min(int(score), 100)

    def _generate_suggestion(self, result: TestResult) -> str:
        """根据评分生成建议。"""
        if result.china_score >= 90: return "优秀节点，强烈推荐"
        elif result.china_score >= 70: return "良好节点，推荐使用"
        elif result.china_score >= 50: return "一般节点，备用选择"
        elif result.china_score >= 20: return "质量较差，可能不稳定"
        else: return "不可用节点，不推荐"

    async def test_single_node_async(self, url: str) -> TestResult:
        """异步测试单个节点。"""
        async with self.sem: # 获取一个信号量槽位
            logger.debug(f"开始测试: {url}")
            try:
                node_info = self.parse_node(url)
                if not node_info or not node_info.address or not node_info.port:
                    return TestResult(
                        node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                        error_message="解析节点失败或缺少地址/端口"
                    )
                
                result = TestResult(node_info=node_info)
                
                # 1. 基础 TCP 连接性测试
                result.basic_connectivity, result.latency_ms, error = await self._test_basic_connectivity_async(node_info)
                if not result.basic_connectivity:
                    result.error_message = error
                    result.china_score = self._calculate_china_score(result)
                    result.suggestion = self._generate_suggestion(result)
                    return result
                
                # 2. SSL 握手测试 (如果适用)
                if (node_info.protocol in ['vmess', 'vless', 'trojan', 'hysteria2'] and node_info.security == 'tls') or node_info.port == 443:
                    result.ssl_handshake, ssl_info = await self._test_ssl_handshake_async(node_info)
                    if not result.ssl_handshake:
                        result.error_message = ssl_info
                        result.china_score = self._calculate_china_score(result)
                        result.suggestion = self._generate_suggestion(result)
                        return result
                else: # 不需要 TLS，SSL 握手默认视为成功
                    result.ssl_handshake = True
                
                # 3. 协议参数验证
                result.protocol_test, protocol_info = self._test_protocol_specific(node_info)
                if not result.protocol_test:
                    result.error_message = protocol_info
                    result.china_score = self._calculate_china_score(result)
                    result.suggestion = self._generate_suggestion(result)
                    return result

                # 4. 模拟 HTTP 代理测试 (基于之前的阶段)
                result.http_proxy_test, _, http_info = await self._test_http_proxy_async(result) 
                if not result.http_proxy_test:
                    result.error_message = http_info


                # 最终评分计算和建议
                result.china_score = self._calculate_china_score(result)
                result.is_china_usable = result.china_score >= 40 # 可用性阈值
                result.suggestion = self._generate_suggestion(result)
                
                return result
                
            except Exception as e:
                logger.error(f"测试节点 {url[:80]}... 时发生错误: {e}")
                return TestResult(
                    node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                    error_message=f"测试意外失败: {str(e)}"
                )

    async def check_nodes_batch_async(self, nodes: List[str]) -> List[Dict]:
        """异步检查一批节点。"""
        logger.info(f"开始对 {len(nodes)} 个节点进行增强检测...")
        
        tasks = [self.test_single_node_async(node_url) for node_url in nodes]
        results: List[TestResult] = []
        completed_count = 0

        # 使用 asyncio.as_completed 获取已完成的结果
        for future in asyncio.as_completed(tasks):
            test_result = await future
            results.append(test_result)
            completed_count += 1
            if completed_count % 50 == 0 or completed_count == len(nodes):
                usable_count = len([r for r in results if r.is_china_usable])
                avg_score = sum(r.china_score for r in results) / len(results) if results else 0
                logger.info(f"进度: {completed_count}/{len(nodes)}, 可用: {usable_count}, 平均评分: {avg_score:.1f}")

        # 将 TestResult 对象转换为字典，以便输出一致
        dict_results = []
        for res in results:
            dict_results.append({
                'url': res.node_info.url,
                'protocol': res.node_info.protocol,
                'address': res.node_info.address,
                'port': res.node_info.port,
                'remarks': res.node_info.remarks,
                'success': res.is_china_usable, # 整体可用性
                'latency': res.latency_ms,
                'china_score': res.china_score,
                'china_usable': res.is_china_usable,
                'suggestion': res.suggestion,
                'error': res.error_message,
                'basic_connectivity': res.basic_connectivity,
                'ssl_handshake': res.ssl_handshake,
                'protocol_test': res.protocol_test,
                'http_proxy_test': res.http_proxy_test,
                # 包含 node_info 对象以供后续 YAML 转换
                'node_info': res.node_info 
            })
        
        # 按 china_score 降序排序 (最高分优先)
        dict_results.sort(key=lambda x: x['china_score'], reverse=True)
        
        usable_final_count = len([r for r in dict_results if r['china_usable']])
        logger.info(f"检测完成！可用节点数: {usable_final_count}/{len(dict_results)}")
        
        return dict_results

    def get_test_targets(self) -> List[str]:
        """根据 china_mode 获取测试目标。"""
        return self.china_test_targets if self.china_mode else self.global_test_targets

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

def save_nodes_to_clash_yaml(nodes_data: List[Dict], filename: str = "sc/all.yaml"):
    """
    将经过验证的节点列表保存到 Clash 兼容的 YAML 配置文件中。
    :param nodes_data: 来自 EnhancedNodeTester's check_nodes_batch_async 的字典列表。
    :param filename: 目标 YAML 文件路径。
    """
    if not nodes_data:
        logger.warning("没有可用的节点数据保存到 YAML。")
        return

    clash_proxies = []
    for node_dict in nodes_data:
        # 从测试结果字典中提取 NodeInfo 对象
        node_info = node_dict.get('node_info')
        if node_info:
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
        logger.info(f"成功保存 {len(clash_proxies)} 个可用节点到 {filename}")
    except Exception as e:
        logger.error(f"保存 YAML 文件失败: {e}")

# --- 主执行 ---

async def main():
    logger.info("启动节点获取和测试过程...")

    all_raw_nodes: List[str] = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_nodes_from_url(session, source_url) for source_url in NODE_SOURCES]
        fetched_lists = await asyncio.gather(*tasks)
        for nodes_list in fetched_lists:
            all_raw_nodes.extend(nodes_list)
    
    # 去重
    all_raw_nodes = list(dict.fromkeys(all_raw_nodes))
    logger.info(f"从所有来源获取到 {len(all_raw_nodes)} 个唯一节点。")

    if not all_raw_nodes:
        logger.warning("没有获取到节点。退出。")
        return

    # 创建 EnhancedNodeTester 实例，并使用修改后的超时和并发任务数
    # timeout: 增加超时时间以应对可能较慢的节点
    # max_concurrent_tasks: 减少并发任务数以降低资源消耗和避免卡顿
    async with EnhancedNodeTester(timeout=20, max_concurrent_tasks=30) as tester:
        all_test_results = await tester.check_nodes_batch_async(all_raw_nodes)
    
    # 筛选出基于 china_score 阈值 (>= 40) 被认为可用的节点
    usable_nodes_for_clash = [
        result for result in all_test_results
        if result['china_usable'] # 直接检查 china_usable 字段
    ]

    if usable_nodes_for_clash:
        # 将可用节点保存为 Clash YAML 文件
        save_nodes_to_clash_yaml(usable_nodes_for_clash)
    else:
        logger.info("没有找到可用的节点来生成 Clash YAML 文件。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("脚本被用户中断。")
    except Exception as e:
        logger.critical(f"脚本执行过程中发生严重错误: {e}")
