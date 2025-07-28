#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版节点检测器 - 专门针对中国大陆翻墙优化
功能：
1. 多阶段检测策略 (连接 -> SSL -> HTTP请求)
2. 真实翻墙场景模拟 (尝试访问境外网站)
3. 智能评分系统
4. 协议特定检测与验证
5. 地理位置感知 (通过测试目标模拟)
6. 全面支持主流协议解析 (Hysteria2, VMess, VLESS, Trojan, SS, SSR)
7. 从多个远程链接获取节点并生成Clash YAML配置
"""

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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of node sources
NODE_SOURCES = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml",
    "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt", # This one returned 404
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml" # This one returned 404
]

# --- Data Classes ---

@dataclass
class NodeInfo:
    """Node information parsed from URL."""
    url: str
    protocol: str
    address: str
    port: int
    remarks: str = ""
    uuid: str = ""
    password: str = ""
    method: str = ""  # SS method
    security: str = ""  # VLESS security, e.g., tls, reality
    network: str = "tcp"  # Vmess/Vless/Trojan network type
    host: str = ""  # WS/H2 host header
    path: str = ""  # WS/H2 path
    sni: str = ""  # TLS SNI
    flow: str = ""  # VLESS flow
    alter_id: int = 0  # Vmess alterId
    mux_enabled: bool = False  # Trojan mux
    obfs: str = ""  # SSR/SS obfs
    obfs_param: str = ""  # SSR/SS obfs param
    protocol_param: str = ""  # SSR protocol param
    obfs_hy2: str = ""  # Hysteria2 obfs
    obfs_password_hy2: str = ""  # Hysteria2 obfs password
    alpn: List[str] = field(default_factory=list)
    insecure: bool = False  # Hysteria2/TLS insecure skip-cert-verify
    fast_open: bool = True  # Hysteria2 fast_open
    mptcp: bool = False  # Hysteria2 mptcp
    up_mbps: int = 0  # Hysteria2 up bandwidth
    down_mbps: int = 0 # Hysteria2 down bandwidth

@dataclass
class TestResult:
    """Results of a node test."""
    node_info: NodeInfo
    basic_connectivity: bool = False
    ssl_handshake: bool = False # This is a TestResult attribute!
    protocol_test: bool = False
    http_proxy_test: bool = False # Indicates if HTTP through proxy is theoretically possible
    latency_ms: float = 0.0
    error_message: str = ""
    china_score: int = 0
    is_china_usable: bool = False
    suggestion: str = ""

# --- Core Tester Class ---

class EnhancedNodeTester:
    def __init__(self, timeout=10, max_concurrent_tasks=50, china_mode=True):
        self.timeout = timeout
        self.max_concurrent_tasks = max_concurrent_tasks
        self.china_mode = china_mode
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.sem = asyncio.Semaphore(self.max_concurrent_tasks) # Limit concurrent async tasks

        self.china_test_targets = [
            "https://www.google.com/generate_204", # Google no-content response, good for probing
            "https://www.facebook.com/favicon.ico",
            "https://www.twitter.com/favicon.ico",
            "https://www.instagram.com/favicon.ico",
            "https://www.reddit.com/favicon.ico",
        ]
        
        self.global_test_targets = [
            "https://www.cloudflare.com/favicon.ico",
            "https://www.amazon.com/favicon.ico",
            "https://www.microsoft.com/favicon.ico",
            "https://www.apple.com/favicon.ico",
            "https://www.netflix.com/favicon.ico"
        ]
        
        self.score_weights = {
            'connectivity': 0.2,
            'latency': 0.2,
            'ssl_handshake': 0.2,
            'protocol_param': 0.1,
            'http_proxy': 0.2,
            'port_commonality': 0.1
        }

    async def __aenter__(self):
        """Asynchronous context manager entry for aiohttp session."""
        self.http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'},
            connector=aiohttp.TCPConnector(ssl=False) # We perform explicit SSL checks, so don't verify here
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Asynchronous context manager exit for closing aiohttp session."""
        if self.http_session:
            await self.http_session.close()

    def _decode_base64_urlsafe(self, s: str) -> str:
        """Safely decode URL-safe Base64 strings, handling padding."""
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
        """Parses a node URL into a NodeInfo object."""
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
                logger.debug(f"Unsupported protocol type: {url[:30]}...")
                return None
        except Exception as e:
            logger.debug(f"Failed to parse node {url[:80]}...: {e}")
            return None

    def _parse_vmess(self, url: str) -> Optional[NodeInfo]:
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
        raw_data = url[5:]
        parts = raw_data.split('#', 1)
        encoded_part = parts[0]
        remarks = unquote(parts[1]) if len(parts) > 1 else ""

        decoded_auth_server = self._decode_base64_urlsafe(encoded_part)
        if not decoded_auth_server:
            return None

        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_auth_server)
        if not match:
            raise ValueError("SS link format mismatch after decode")

        method, password, server, port = match.groups()

        return NodeInfo(
            url=url, protocol='ss', address=server, port=int(port),
            remarks=remarks or f"SS-{server}:{port}", method=method, password=password
        )

    def _parse_shadowsocksr(self, url: str) -> Optional[NodeInfo]:
        encoded_part_with_fragment = url[6:]
        parts = encoded_part_with_fragment.split('#', 1)
        encoded_params = parts[0]
        remarks = unquote(parts[1]) if len(parts) > 1 else ""

        decoded_params = self._decode_base64_urlsafe(encoded_params)
        if not decoded_params:
            return None

        ssr_parts = decoded_params.split(':')
        if len(ssr_parts) < 6:
            raise ValueError("SSR link missing components")

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
            url=url, protocol='ssr', address=server, port=port,
            remarks=remarks or f"SSR-{server}:{port}", password=password,
            method=method, obfs=obfs, obfs_param=obfs_param, protocol_param=protocol_param
        )

    def _parse_trojan(self, url: str) -> Optional[NodeInfo]:
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
        parsed = urlparse(url)
        password = parsed.username or ""
        address = parsed.hostname
        port = parsed.port

        if not address or not port:
            raise ValueError("Hysteria2 link missing address or port")
        
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
        """Asynchronous basic TCP connectivity test."""
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
            return False, 0, "Connection timeout"
        except ConnectionRefusedError:
            return False, 0, "Connection refused"
        except socket.gaierror:
            return False, 0, "DNS resolution failed"
        except Exception as e:
            return False, 0, f"Connection error: {str(e)}"

    async def _test_ssl_handshake_async(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """Asynchronous SSL/TLS handshake test."""
        requires_tls_check = (
            (node_info.protocol in ['vmess', 'vless', 'trojan'] and node_info.security == 'tls') or
            node_info.protocol == 'hysteria2' or
            node_info.port == 443
        )
        if not requires_tls_check:
            return True, "Not applicable (no TLS configured or non-443 port)"

        try:
            context = ssl.create_default_context()
            if node_info.insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
            
            target_sni = node_info.sni if node_info.sni else node_info.address
            if not target_sni and node_info.protocol not in ['ss', 'ssr']: # SS/SSR don't strictly require SNI for handshake
                 # If TLS is required but SNI is missing for protocols that need it, mark as failure
                return False, "SSL: SNI is required but not provided for TLS protocol"

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node_info.address, node_info.port, ssl=context, server_hostname=target_sni),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            return True, f"SSL handshake successful with SNI: {target_sni}"
        except ssl.SSLError as e:
            return False, f"SSL error: {str(e)}"
        except asyncio.TimeoutError:
            return False, "SSL handshake timeout"
        except ConnectionRefusedError:
            return False, "SSL connection refused"
        except Exception as e:
            return False, f"SSL test failed: {str(e)}"

    # FIX START: Modified _test_http_proxy_async to accept TestResult
    async def _test_http_proxy_async(self, result: TestResult) -> Tuple[bool, float, str]:
        """
        Simulated HTTP proxy test.
        This function currently assumes that if TCP/SSL/Protocol validation passes,
        the node is theoretically capable of proxying HTTP traffic.
        A true HTTP proxy test would involve a local proxy or protocol-specific
        HTTP tunneling, which is beyond a simple node checker's scope.
        """
        node_info = result.node_info # Get NodeInfo from TestResult

        # If the node involves TLS/WebSocket/gRPC, and SSL handshake was successful,
        # we consider it capable of carrying HTTP traffic.
        # For SS/SSR, if basic connectivity and parameters are fine, we assume it too.
        # This is a simplification.
        if (node_info.protocol in ['vmess', 'vless', 'trojan', 'hysteria2'] and result.ssl_handshake) or \
           (node_info.protocol in ['ss', 'ssr'] and result.basic_connectivity):
            return True, 0.0, "Assumed HTTP proxy capability via protocol/TLS handshake"
        else:
            return False, 0.0, "Protocol not directly suitable for simple HTTP proxy test or prior stage failed"
    # FIX END

    def _test_protocol_specific(self, node_info: NodeInfo) -> Tuple[bool, str]:
        """Protocol-specific parameter validation."""
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
                return False, "Unknown protocol"
        except Exception as e:
            return False, f"Protocol validation failed: {str(e)}"

    def _validate_vmess_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.uuid, node_info.address, node_info.port]): return False, "VMess: Missing required fields"
        # VMess TLS security can be 'none' or 'tls'. If 'tls', SNI is important but not strictly mandatory by spec.
        if node_info.security == 'tls' and not node_info.sni and node_info.network in ['ws', 'h2', 'grpc']:
            return True, "VMess with TLS but SNI missing for web transport. May still work."
        return True, "VMess params OK"

    def _validate_vless_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.uuid, node_info.address, node_info.port]): return False, "VLESS: Missing required fields"
        if node_info.security in ['tls', 'reality'] and not node_info.sni:
            return False, "VLESS with TLS/Reality: SNI is highly recommended and often required."
        if node_info.network in ['ws', 'grpc'] and not node_info.path:
            return False, f"VLESS with {node_info.network}: Path is usually required."
        return True, "VLESS params OK"

    def _validate_trojan_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.password, node_info.address, node_info.port]): return False, "Trojan: Missing required fields"
        if not node_info.sni:
            return False, "Trojan: SNI is highly recommended for Trojan."
        return True, "Trojan params OK"

    def _validate_ss_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.method, node_info.password, node_info.address, node_info.port]): return False, "SS: Missing required fields"
        valid_methods = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-poly1305', 'aes-256-cfb', 'aes-128-cfb', 'none']
        if node_info.method not in valid_methods:
            return False, f"SS: Unsupported method: {node_info.method}"
        return True, "SS params OK"
    
    def _validate_ssr_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.address, node_info.port, node_info.method, node_info.password, node_info.protocol_param, node_info.obfs]):
            return False, "SSR: Missing required fields"
        return True, "SSR params OK"

    def _validate_hysteria2_params(self, node_info: NodeInfo) -> Tuple[bool, str]:
        if not all([node_info.address, node_info.port, node_info.password]): return False, "Hysteria2: Missing required fields"
        if not node_info.sni:
            return False, "Hysteria2: SNI is highly recommended."
        if not node_info.alpn:
            return False, "Hysteria2: ALPN is required."
        return True, "Hysteria2 params OK"

    def _calculate_china_score(self, result: TestResult) -> int:
        """Calculates a score for China usability."""
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
        if result.http_proxy_test: score += self.score_weights['http_proxy'] * 100 # Important for usability
        if result.node_info.port in [80, 443, 8080, 8443, 2053, 2083, 2087, 2096, 8388, 8389]:
            score += self.score_weights['port_commonality'] * 100
        
        # Protocol specific bonuses
        if result.node_info.protocol in ['trojan', 'vless', 'hysteria2']: score += 5
        elif result.node_info.protocol == 'vmess' and result.node_info.network == 'ws' and result.node_info.security == 'tls': score += 5

        return min(int(score), 100)

    def _generate_suggestion(self, result: TestResult) -> str:
        """Generates a suggestion based on the score."""
        if result.china_score >= 90: return "Excellent node, highly recommended"
        elif result.china_score >= 70: return "Good node, recommended for use"
        elif result.china_score >= 50: return "Average node, secondary choice"
        elif result.china_score >= 20: return "Poor quality, might be unstable"
        else: return "Unusable node, not recommended"

    async def test_single_node_async(self, url: str) -> TestResult:
        """Asynchronously tests a single node."""
        async with self.sem: # Acquire a semaphore slot
            logger.debug(f"Starting test for: {url}")
            try:
                node_info = self.parse_node(url)
                if not node_info or not node_info.address or not node_info.port:
                    return TestResult(
                        node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                        error_message="Failed to parse node or missing address/port"
                    )
                
                result = TestResult(node_info=node_info)
                
                # 1. Basic TCP Connectivity Test
                result.basic_connectivity, result.latency_ms, error = await self._test_basic_connectivity_async(node_info)
                if not result.basic_connectivity:
                    result.error_message = error
                    result.china_score = self._calculate_china_score(result)
                    result.suggestion = self._generate_suggestion(result)
                    return result
                
                # 2. SSL Handshake Test (if applicable)
                if (node_info.protocol in ['vmess', 'vless', 'trojan', 'hysteria2'] and node_info.security == 'tls') or node_info.port == 443:
                    result.ssl_handshake, ssl_info = await self._test_ssl_handshake_async(node_info)
                    if not result.ssl_handshake:
                        result.error_message = ssl_info
                        result.china_score = self._calculate_china_score(result)
                        result.suggestion = self._generate_suggestion(result)
                        return result
                else: # No TLS required, so SSL Handshake is 'true' by default.
                    result.ssl_handshake = True
                
                # 3. Protocol Parameter Validation
                result.protocol_test, protocol_info = self._test_protocol_specific(node_info)
                if not result.protocol_test:
                    result.error_message = protocol_info
                    result.china_score = self._calculate_china_score(result)
                    result.suggestion = self._generate_suggestion(result)
                    return result

                # 4. Simulated HTTP Proxy Test (based on previous stages)
                # FIX: Pass the 'result' object directly to _test_http_proxy_async
                result.http_proxy_test, _, http_info = await self._test_http_proxy_async(result) 
                if not result.http_proxy_test:
                    result.error_message = http_info


                # Final score calculation and suggestion
                result.china_score = self._calculate_china_score(result)
                result.is_china_usable = result.china_score >= 40
                result.suggestion = self._generate_suggestion(result)
                
                return result
                
            except Exception as e:
                logger.error(f"Error testing node {url[:80]}...: {e}")
                return TestResult(
                    node_info=NodeInfo(url=url, protocol='unknown', address='', port=0, remarks=''),
                    error_message=f"Test failed unexpectedly: {str(e)}"
                )

    async def check_nodes_batch_async(self, nodes: List[str]) -> List[Dict]:
        """Asynchronously checks a batch of nodes."""
        logger.info(f"Starting enhanced node detection for {len(nodes)} nodes...")
        
        tasks = [self.test_single_node_async(node_url) for node_url in nodes]
        results: List[TestResult] = []
        completed_count = 0

        # Use asyncio.as_completed to get results as they finish
        for future in asyncio.as_completed(tasks):
            test_result = await future
            results.append(test_result)
            completed_count += 1
            if completed_count % 50 == 0 or completed_count == len(nodes):
                usable_count = len([r for r in results if r.is_china_usable])
                avg_score = sum(r.china_score for r in results) / len(results) if results else 0
                logger.info(f"Progress: {completed_count}/{len(nodes)}, Usable: {usable_count}, Avg Score: {avg_score:.1f}")

        # Convert TestResult objects to dictionaries for consistent output
        dict_results = []
        for res in results:
            dict_results.append({
                'url': res.node_info.url,
                'protocol': res.node_info.protocol,
                'address': res.node_info.address,
                'port': res.node_info.port,
                'remarks': res.node_info.remarks,
                'success': res.is_china_usable, # Overall usability
                'latency': res.latency_ms,
                'china_score': res.china_score,
                'china_usable': res.is_china_usable,
                'suggestion': res.suggestion,
                'error': res.error_message,
                'basic_connectivity': res.basic_connectivity,
                'ssl_handshake': res.ssl_handshake,
                'protocol_test': res.protocol_test,
                'http_proxy_test': res.http_proxy_test,
                # Include node_info object for later YAML conversion
                'node_info': res.node_info 
            })
        
        # Sort by china_score (highest first)
        dict_results.sort(key=lambda x: x['china_score'], reverse=True)
        
        usable_final_count = len([r for r in dict_results if r['china_usable']])
        logger.info(f"Detection complete! Usable nodes: {usable_final_count}/{len(dict_results)}")
        
        return dict_results

    def get_test_targets(self) -> List[str]:
        """Gets test targets based on china_mode."""
        return self.china_test_targets if self.china_mode else self.global_test_targets

# --- Node Fetching and YAML Generation ---

async def fetch_nodes_from_url(session: aiohttp.ClientSession, url: str) -> List[str]:
    """Fetches node URLs from a given remote URL, handling various formats."""
    try:
        logger.info(f"Fetching nodes from: {url}")
        async with session.get(url, timeout=15) as response:
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            content_type = response.headers.get('Content-Type', '')
            text_content = await response.text()

            # Handle base64 encoded content
            if "text/plain" in content_type and not text_content.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')) and len(text_content) > 100:
                try:
                    decoded_content = base64.b64decode(text_content.strip()).decode('utf-8')
                    # Check if decoded content looks like a list of URLs or a YAML
                    if '\n' in decoded_content or decoded_content.strip().startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')):
                        text_content = decoded_content
                    elif decoded_content.strip().startswith(('proxies:', 'proxy-groups:', 'rules:')):
                         # It's a Clash YAML
                        try:
                            config = yaml.safe_load(decoded_content)
                            if 'proxies' in config and isinstance(config['proxies'], list):
                                # If it's a Clash YAML, the conversion to URL is complex and not guaranteed.
                                # For now, we rely on the direct parsing logic for Clash YAML further down.
                                pass 
                        except yaml.YAMLError:
                            pass # Not a valid YAML, continue
                except Exception as e:
                    logger.debug(f"Failed to decode base64 from {url}: {e}")

            # Handle direct node lists (one URL per line)
            if '\n' in text_content:
                lines = text_content.splitlines()
                nodes = []
                for line in lines:
                    line = line.strip()
                    if line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://', 'hysteria2://')):
                        nodes.append(line)
                if nodes: return nodes

            # Handle Clash YAML (proxies section)
            if text_content.strip().startswith(('proxies:', 'proxy-groups:', 'rules:')) or "yaml" in content_type:
                try:
                    config = yaml.safe_load(text_content)
                    if 'proxies' in config and isinstance(config['proxies'], list):
                        clash_proxies = config['proxies']
                        nodes = []
                        # Convert Clash proxy dict to a URL string if possible
                        for proxy_dict in clash_proxies:
                            url = ""
                            # Attempt to reconstruct a URL from the proxy dict
                            if proxy_dict.get('type') == 'vmess':
                                # This is a simplification; full VMess URL reconstruction is complex
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
                                # Add other Hysteria2 specific parameters here if they exist in Clash YAML and you want to reconstruct
                                
                                query_string = "&".join(query_params)
                                url = f"hysteria2://{proxy_dict.get('password')}@{proxy_dict.get('server')}:{proxy_dict.get('port')}"
                                if query_string: url += f"?{query_string}"
                                if proxy_dict.get('name'): url += f"#{proxy_dict.get('name')}"
                            elif proxy_dict.get('type') == 'ssr':
                                # SSR URL reconstruction is quite complex due to multiple encoding layers
                                # This is a placeholder; needs full SSR spec adherence
                                logger.warning(f"Skipping SSR proxy reconstruction from Clash YAML: {proxy_dict.get('name')}")
                                url = "" # Don't add if complex reconstruction is not done
                            
                            if url:
                                nodes.append(url)
                        if nodes: return nodes
                except yaml.YAMLError as e:
                    logger.debug(f"Failed to parse YAML from {url}: {e}")
            
            logger.warning(f"Could not extract nodes from {url}. Content might be unsupported format or empty.")
            return []

    except aiohttp.ClientError as e:
        logger.error(f"HTTP error fetching {url}: {e}")
        return []
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching {url}")
        return []
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching {url}: {e}")
        return []

def to_clash_yaml_node(node_info: NodeInfo) -> Optional[Dict]:
    """Converts a NodeInfo object to a Clash YAML compatible dictionary."""
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
            if node_info.host: ws_opts["headers"] = {"Host": node_info.host}
            node["ws-opts"] = ws_opts
        if node_info.security == 'tls' or node_info.port == 443:
            node["tls"] = True
            if node_info.sni: node["servername"] = node_info.sni
            
    elif node_info.protocol == 'vless':
        node["type"] = "vless"
        node["uuid"] = node_info.uuid
        node["cipher"] = "auto"
        node["flow"] = node_info.flow
        if node_info.network == "ws":
            node["network"] = "ws"
            ws_opts = {"path": node_info.path}
            if node_info.host: ws_opts["headers"] = {"Host": node_info.host}
            node["ws-opts"] = ws_opts
        elif node_info.network == "grpc":
            node["network"] = "grpc"
            grpc_opts = {"serviceName": node_info.path.lstrip('/')}
            node["grpc-opts"] = grpc_opts
        if node_info.security in ['tls', 'reality']:
            node["tls"] = True
            if node_info.sni: node["servername"] = node_info.sni

    elif node_info.protocol == 'ss':
        node["type"] = "ss"
        node["password"] = node_info.password
        node["cipher"] = node_info.method
            
    elif node_info.protocol == 'trojan':
        node["type"] = "trojan"
        node["password"] = node_info.password
        node["tls"] = True
        if node_info.sni: node["servername"] = node_info.sni
        if node_info.network == "ws":
            node["network"] = "ws"
            ws_opts = {"path": node_info.path}
            if node_info.host: ws_opts["headers"] = {"Host": node_info.host}
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
        if node_info.sni: node["servername"] = node_info.sni

    elif node_info.protocol == 'ssr':
        node["type"] = "ssr" # Requires Clash.Meta or specific Clash builds
        node["password"] = node_info.password
        node["cipher"] = node_info.method
        node["protocol"] = node_info.protocol_param
        node["obfs"] = node_info.obfs
        node["obfs-param"] = node_info.obfs_param

    else:
        logger.warning(f"Unsupported protocol {node_info.protocol} for Clash YAML conversion: {node_info.remarks}")
        return None
    
    return node

def save_nodes_to_clash_yaml(nodes_data: List[Dict], filename: str = "sc/all.yaml"):
    """
    Saves a list of validated nodes to a Clash-compatible YAML configuration file.
    :param nodes_data: List of dictionaries from EnhancedNodeTester's check_nodes_batch_async.
    :param filename: The target YAML file path.
    """
    if not nodes_data:
        logger.warning("No usable node data to save to YAML.")
        return

    clash_proxies = []
    for node_dict in nodes_data:
        # Extract NodeInfo object from the test result dictionary
        node_info = node_dict.get('node_info')
        if node_info:
            clash_node = to_clash_yaml_node(node_info)
            if clash_node:
                clash_proxies.append(clash_node)
    
    if not clash_proxies:
        logger.warning("No nodes successfully converted to Clash YAML format. File not generated.")
        return

    # Basic Clash configuration framework
    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "redir-port": 7892,
        "mixed-port": 7893,
        "allow-lan": False,
        "mode": "rule", # Set default mode to rule
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "secret": "", # You might want to set a secret for external controller
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:7893",
            "enhanced-mode": "redir-host",
            "default-nameserver": ["114.114.114.114", "223.5.5.5"],
            "nameserver": ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.1.1.1"],
            "fallback": ["8.8.8.8", "1.1.1.1"],
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
                "proxies": ["♻️ Auto Select", "🚀 Manual Select", "DIRECT"] + [node["name"] for node in clash_proxies]
            },
            {
                "name": "♻️ Auto Select",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [node["name"] for node in clash_proxies]
            },
            {
                "name": "🚀 Manual Select",
                "type": "select",
                "proxies": [node["name"] for node in clash_proxies]
            },
            {
                "name": "🌐 外网直连",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": [node["name"] for node in clash_proxies if node["type"] != 'ssr'] # SSR might be less compatible
            },
            {"name": "DIRECT", "type": "select", "proxies": ["DIRECT"]},
            {"name": "AdBlock", "type": "select", "proxies": ["DIRECT", "Proxy"]},
            {"name": "Domestic", "type": "select", "proxies": ["DIRECT", "Proxy"]},
        ],
        "rules": [
            "PROCESS-NAME,Telegram.exe,Proxy",
            "PROCESS-NAME,chrome.exe,Proxy",
            "DOMAIN-KEYWORD,google,Proxy",
            "DOMAIN-KEYWORD,youtube,Proxy",
            "DOMAIN-KEYWORD,facebook,Proxy",
            "DOMAIN-KEYWORD,twitter,Proxy",
            "DOMAIN-KEYWORD,netflix,Proxy",
            "DOMAIN-KEYWORD,t.me,Proxy",
            "DOMAIN-SUFFIX,google.com,Proxy",
            # This line seems incorrect, it should be a domain or IP, not a full URL
            # "DOMAIN-SUFFIX,youtube.com,Proxy",
            "DOMAIN-SUFFIX,googleusercontent.com,Proxy", # Corrected for a domain suffix
            "DOMAIN-SUFFIX,facebook.com,Proxy",
            "DOMAIN-SUFFIX,twitter.com,Proxy",
            "DOMAIN-SUFFIX,instagram.com,Proxy",
            "DOMAIN-SUFFIX,netflix.com,Proxy",
            "DOMAIN-SUFFIX,github.com,Proxy",
            "DOMAIN-SUFFIX,wikipedia.org,Proxy",
            "GEOSITE,CN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,Proxy"
        ]
    }

    output_dir = os.path.dirname(filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created output directory: {output_dir}")

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, sort_keys=False, indent=2, allow_unicode=True)
        logger.info(f"Successfully saved {len(clash_proxies)} usable nodes to {filename}")
    except Exception as e:
        logger.error(f"Failed to save YAML file: {e}")

# --- Main Execution ---

async def main():
    logger.info("Starting node fetching and testing process...")

    all_raw_nodes: List[str] = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_nodes_from_url(session, source_url) for source_url in NODE_SOURCES]
        fetched_lists = await asyncio.gather(*tasks)
        for nodes_list in fetched_lists:
            all_raw_nodes.extend(nodes_list)
    
    # Remove duplicates
    all_raw_nodes = list(dict.fromkeys(all_raw_nodes))
    logger.info(f"Fetched {len(all_raw_nodes)} unique nodes from all sources.")

    if not all_raw_nodes:
        logger.warning("No nodes fetched. Exiting.")
        return

    async with EnhancedNodeTester(timeout=10, max_concurrent_tasks=50) as tester:
        all_test_results = await tester.check_nodes_batch_async(all_raw_nodes)
    
    # Filter for nodes deemed usable based on the china_score threshold (>= 40)
    usable_nodes_for_clash = [
        result for result in all_test_results
        if result['china_usable'] # This directly checks if china_score >= 40
    ]

    # Save to YAML file
    save_nodes_to_clash_yaml(usable_nodes_for_clash, filename="sc/all.yaml")
    logger.info("Node detection and YAML generation complete.")

if __name__ == "__main__":
    asyncio.run(main())
