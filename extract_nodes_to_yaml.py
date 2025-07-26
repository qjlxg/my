
import aiohttp
import asyncio
import base64
import json
import yaml
import os
import re
import platform
from urllib.parse import urlparse, unquote
from typing import List, Dict, Any

# 定义支持的协议
SUPPORTED_PROTOCOLS = {'hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless'}

async def fetch_url(session: aiohttp.ClientSession, url: str) -> str:
    """异步获取 URL 内容"""
    try:
        async with session.get(url, timeout=30) as response:
            if response.status == 200:
                return await response.text()
            else:
                print(f"Failed to fetch {url}: Status {response.status}")
                return ""
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        return ""

def parse_vmess(data: str) -> Dict[str, Any]:
    """解析 vmess 协议"""
    try:
        decoded = base64.b64decode(data).decode('utf-8')
        return json.loads(decoded)
    except:
        return {}

def parse_trojan(data: str) -> Dict[str, Any]:
    """解析 trojan 协议"""
    try:
        parts = urlparse(data)
        return {
            'name': unquote(parts.fragment) or 'trojan_node',
            'server': parts.hostname,
            'port': parts.port or 443,
            'password': parts.netloc.split('@')[0]
        }
    except:
        return {}

def parse_ss(data: str) -> Dict[str, Any]:
    """解析 ss 协议"""
    try:
        if '@' in data:
            auth, addr = data.split('@')
            method, password = auth.split(':')
            server, port = addr.split(':')
            return {
                'name': 'ss_node',
                'server': server,
                'port': int(port.split('#')[0]),
                'method': method,
                'password': unquote(password)
            }
        return {}
    except:
        return {}

def parse_vless(data: str) -> Dict[str, Any]:
    """解析 vless 协议"""
    try:
        parts = urlparse(data)
        return {
            'name': unquote(parts.fragment) or 'vless_node',
            'server': parts.hostname,
            'port': parts.port or 443,
            'uuid': parts.netloc.split('@')[0]
        }
    except:
        return {}

def parse_hysteria2(data: str) -> Dict[str, Any]:
    """解析 hysteria2 协议"""
    try:
        parts = urlparse(data)
        return {
            'name': unquote(parts.fragment) or 'hysteria2_node',
            'server': parts.hostname,
            'port': parts.port or 443,
            'password': parts.netloc.split('@')[0]
        }
    except:
        return {}

def parse_ssr(data: str) -> Dict[str, Any]:
    """解析 ssr 协议"""
    try:
        decoded = base64.b64decode(data).decode('utf-8')
        parts = decoded.split(':')
        return {
            'name': 'ssr_node',
            'server': parts[0],
            'port': int(parts[1]),
            'protocol': parts[2],
            'method': parts[3],
            'obfs': parts[4],
            'password': base64.b64decode(parts[5].split('/')[0]).decode('utf-8')
        }
    except:
        return {}

def parse_node(line: str) -> List[Dict[str, Any]]:
    """解析单行节点"""
    nodes = []
    line = line.strip()
    if not line:
        return nodes

    # 尝试解析协议
    for protocol in SUPPORTED_PROTOCOLS:
        if line.startswith(f"{protocol}://"):
            data = line[len(protocol) + 3:]
            parser = {
                'vmess': parse_vmess,
                'trojan': parse_trojan,
                'ss': parse_ss,
                'vless': parse_vless,
                'hysteria2': parse_hysteria2,
                'ssr': parse_ssr
            }.get(protocol)
            if parser:
                node = parser(data)
                if node:
                    node['type'] = protocol
                    nodes.append(node)
            break
    else:
        # 尝试几次 Base64 解码
        try:
            decoded = line

            for _ in range(3):  # 尝试解码最多三次
                try:
                    decoded = base64.b64decode(decoded).decode('utf-8')
                except:
                    break
            for protocol in SUPPORTED_PROTOCOLS:
                if decoded.startswith(f"{protocol}://"):
                    nodes.extend(parse_node(decoded))
                    break
        except:
            pass
    return nodes

def parse_content(content: str, url: str) -> List[Dict[str, Any]]:
    """解析内容，可能包含多行节点、YAML 或 JSON"""
    nodes = []
    
    # 尝试解析 YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data:
            nodes.extend(data['proxies'])
        elif isinstance(data, list):
            nodes.extend(data)
        return nodes
    except:
        pass

    # 尝试解析 JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict) and 'proxies' in data:
            nodes.extend(data['proxies'])
        elif isinstance(data, list):
            nodes.extend(data)
        return nodes
    except:
        pass

    # 按行解析（可能是 Base64 编码的多行节点）
    for line in content.splitlines():
        nodes.extend(parse_node(line))

    return nodes

def save_to_yaml(nodes: List[Dict[str, Any]], filename: str):
    """保存节点到 YAML 文件"""
    if not nodes:
        print(f"No nodes to save for {filename}")
        return
    
    yaml_data = {'proxies': nodes}
    os.makedirs('sc', exist_ok=True)
    filepath = os.path.join('sc', filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(yaml_data, f, allow_unicode=True, sort_keys=False)
    print(f"Saved {len(nodes)} nodes to {filepath}")

async def process_url(session: aiohttp.ClientSession, url: str):
    """处理单个 URL"""
    content = await fetch_url(session, url)
    if not content:
        return

    # 根据 URL 路径确定输出文件名
    parsed_url = urlparse(url)
    path = parsed_url.path
    filename = 'list_raw.yaml' if 'list_raw.txt' in path else 'nodes.yaml'
    
    # 解析内容
    nodes = parse_content(content, url)
    save_to_yaml(nodes, filename)

async def main():
    urls = [
        "https://igdux.top/~250630",
        "https://igdux.top/~250701-534",
        "https://igdux.top/~250717",
        "https://igdux.top/~250719",
        "https://igdux.top/~ha_250718",
        "https://igdux.top/RDpP",
        "https://igdux.top/XGEN",
        "https://igdux.top/zzCe",
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
        "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/output/all_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/data/all_unique_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/merged_configs.txt",
        "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list_raw.txt",
        "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    ]

    async with aiohttp.ClientSession() as session:
        tasks = [process_url(session, url) for url in urls]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())

