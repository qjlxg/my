import aiohttp
import asyncio
import base64
import json
import yaml
import os
import re
import platform
from urllib.parse import urlparse, unquote, parse_qs
from typing import List, Dict, Any, Optional
from collections import defaultdict

# 定义支持的协议
SUPPORTED_PROTOCOLS = {'hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless'}

async def fetch_url(session: aiohttp.ClientSession, url: str) -> str:
    """异步获取 URL 内容"""
    print(f"Fetching from {url}")
    try:
        async with session.get(url, timeout=30) as response:
            if response.status == 200:
                print(f"Successfully fetched {url}")
                return await response.text()
            else:
                print(f"Failed to fetch {url}: Status {response.status}")
                return ""
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        return ""

def generate_node_name(protocol: str, server: Optional[str] = None, port: Optional[int] = None) -> str:
    """生成默认节点名称，处理 server 和 port 可能为 None 的情况"""
    server_str = server if server else "unknown_server"
    port_str = str(port) if port is not None else "unknown_port"
    return f"{protocol}-{server_str}:{port_str}"

def ensure_node_name(node: Dict[str, Any], protocol: str) -> Dict[str, Any]:
    """确保节点字典中存在 'name' 字段，如果缺失则生成"""
    if 'name' not in node or not node['name']:
        server = node.get('server')
        port = node.get('port')
        node['name'] = generate_node_name(protocol, server, port)
        print(f"Warning: Node missing name, generated: {node['name']}")
    return node

def parse_vmess(data: str) -> Optional[Dict[str, Any]]:
    """解析 vmess 协议"""
    try:
        decoded_data = base64.b64decode(data + '==').decode('utf-8')
        config = json.loads(decoded_data)
        
        server = config.get('add')
        port = int(config.get('port', 0))
        
        node = {
            'name': config.get('ps', generate_node_name('vmess', server, port)),
            'type': 'vmess',
            'server': server,
            'port': port,
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': 'auto'
        }

        if config.get('tls') == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = bool(config.get('scy', False))
            if 'host' in config and config['host']:
                node['sni'] = config['host']
            
            if 'fp' in config and config['fp']:
                node['client-fingerprint'] = config['fp']
            elif 'fingerprint' in config and config['fingerprint']:
                node['client-fingerprint'] = config['fingerprint']

        network = config.get('net')
        if network:
            node['network'] = network
            if network == 'ws':
                node['ws-path'] = config.get('path', '/')
                if 'host' in config and config['host']:
                    node['ws-headers'] = {'Host': config['host']}
            elif network == 'grpc':
                node['grpc-service-name'] = config.get('path', '')
        
        return ensure_node_name(node, 'vmess')
    except Exception as e:
        print(f"Error parsing vmess data '{data[:50]}...': {e}")
        return None

def parse_trojan(data: str) -> Optional[Dict[str, Any]]:
    """解析 trojan 协议"""
    try:
        parsed_url = urlparse("trojan://" + data)
        
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('trojan', server, port)
        
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'tls': True
        }
        
        node['skip-cert-verify'] = (params.get('allowInsecure', ['0'])[0] == '1')
        if 'sni' in params:
            node['sni'] = params['sni'][0]
        
        if 'fp' in params:
            node['client-fingerprint'] = params['fp'][0]
        
        if 'alpn' in params:
            node['alpn'] = params['alpn'][0].split(',')

        return ensure_node_name(node, 'trojan')
    except Exception as e:
        print(f"Error parsing trojan data '{data[:50]}...': {e}")
        return None

def parse_ss(data: str) -> Optional[Dict[str, Any]]:
    """解析 ss 协议"""
    try:
        parts = data.split('#', 1)
        encoded_info = parts[0]
        
        decoded_info = base64.b64decode(encoded_info + '==').decode('utf-8')
        
        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_info)
        if match:
            method, password, server, port_str = match.groups()
            port = int(port_str)
            node_name_from_fragment = unquote(parts[1]) if len(parts) > 1 else None
            
            node = {
                'name': node_name_from_fragment if node_name_from_fragment else generate_node_name('ss', server, port),
                'type': 'ss',
                'server': server,
                'port': port,
                'cipher': method,
                'password': password
            }
            return ensure_node_name(node, 'ss')
        else:
            print(f"SS data format not recognized: {decoded_info[:50]}...")
            return None
    except Exception as e:
        print(f"Error parsing ss data '{data[:50]}...': {e}")
        return None

def parse_vless(data: str) -> Optional[Dict[str, Any]]:
    """解析 vless 协议"""
    try:
        parsed_url = urlparse("vless://" + data)
        
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('vless', server, port)
        
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid
        }

        if params.get('security', [''])[0] == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = (params.get('allowInsecure', ['0'])[0] == '1')
            if 'sni' in params:
                node['sni'] = params['sni'][0]
            
            if 'fp' in params:
                node['client-fingerprint'] = params['fp'][0]
            elif 'fingerprint' in params:
                node['client-fingerprint'] = params['fingerprint'][0]

        network = params.get('type', [''])[0]
        if network:
            node['network'] = network
            if network == 'ws':
                node['ws-path'] = params.get('path', ['/'])[0]
                if 'host' in params and params['host'][0]:
                    node['ws-headers'] = {'Host': params['host'][0]}
            elif network == 'grpc':
                node['grpc-service-name'] = params.get('serviceName', [''])[0]
        
        if 'flow' in params:
            node['flow'] = params['flow'][0]

        return ensure_node_name(node, 'vless')
    except Exception as e:
        print(f"Error parsing vless data '{data[:50]}...': {e}")
        return None

def parse_hysteria2(data: str) -> Optional[Dict[str, Any]]:
    """解析 hysteria2 协议"""
    try:
        parsed_url = urlparse("hysteria2://" + data)
        
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('hysteria2', server, port)
        
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'tls': True
        }
        
        node['skip-cert-verify'] = (params.get('insecure', ['0'])[0] == '1')
        if 'sni' in params:
            node['sni'] = params['sni'][0]
        if 'alpn' in params:
            node['alpn'] = params['alpn'][0].split(',')
        if 'fastopen' in params:
            node['fast-open'] = (params.get('fastopen', ['0'])[0] == '1')
        
        if 'fingerprint' in params:
            node['client-fingerprint'] = params['fingerprint'][0]

        return ensure_node_name(node, 'hysteria2')
    except Exception as e:
        print(f"Error parsing hysteria2 data '{data[:50]}...': {e}")
        return None

def parse_ssr(data: str) -> Optional[Dict[str, Any]]:
    """解析 ssr 协议"""
    try:
        decoded_data = base64.b64decode(data.replace('-', '+').replace('_', '/') + '==').decode('utf-8')
        
        parts = decoded_data.split(':')
        if len(parts) < 6:
            print(f"SSR data has too few parts: {decoded_data[:50]}...")
            return None

        server = parts[0]
        port = int(parts[1])
        protocol_type = parts[2]
        method = parts[3]
        obfs = parts[4]
        
        password_encoded_and_params = parts[5]
        password_base64 = password_encoded_and_params.split('/?')[0]
        password = base64.b64decode(password_base64.replace('-', '+').replace('_', '/') + '==').decode('utf-8')

        params = {}
        if '/?' in password_encoded_and_params:
            query_string = password_encoded_and_params.split('/?')[1]
            params = parse_qs(query_string)
        
        name_encoded = params.get('remarks', [''])[0]
        node_name = unquote(base64.b64decode(name_encoded.replace('-', '+').replace('_', '/') + '==').decode('utf-8')) if name_encoded else generate_node_name('ssr', server, port)
        
        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param = unquote(base64.b64decode(obfs_param_encoded.replace('-', '+').replace('_', '/') + '==').decode('utf-8')) if obfs_param_encoded else ''
        
        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param = unquote(base64.b64decode(protocol_param_encoded.replace('-', '+').replace('_', '/') + '==').decode('utf-8')) if protocol_param_encoded else ''

        node = {
            'name': node_name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'protocol': protocol_type,
            'protocol-param': protocol_param,
            'obfs': obfs,
            'obfs-param': obfs_param
        }
        return ensure_node_name(node, 'ssr')
    except Exception as e:
        print(f"Error parsing ssr data '{data[:50]}...': {e}")
        return None

def parse_line_as_node(line: str) -> List[Dict[str, Any]]:
    """尝试将单行字符串解析为一个或多个节点"""
    nodes = []
    line = line.strip()
    if not line:
        return nodes

    for protocol in SUPPORTED_PROTOCOLS:
        if line.startswith(f"{protocol}://"):
            data_part = line[len(protocol) + 3:]
            
            parser = {
                'vmess': parse_vmess,
                'trojan': parse_trojan,
                'ss': parse_ss,
                'vless': parse_vless,
                'hysteria2': parse_hysteria2,
                'ssr': parse_ssr
            }.get(protocol)

            if parser:
                node = parser(data_part)
                if node:
                    nodes.append(node)
                else:
                    print(f"Failed to parse {protocol} node from line: {line[:100]}...")
            return nodes

    decoded_content = line
    for _ in range(5):
        try:
            temp_decoded = base64.b64decode(decoded_content + '==').decode('utf-8')
            for protocol in SUPPORTED_PROTOCOLS:
                if temp_decoded.startswith(f"{protocol}://"):
                    nodes.extend(parse_line_as_node(temp_decoded))
                    return nodes
            decoded_content = temp_decoded
        except Exception:
            break
    return nodes

def parse_content(content: str) -> List[Dict[str, Any]]:
    """解析内容，可能包含多行节点、YAML 或 JSON"""
    nodes: List[Dict[str, Any]] = []
    
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                    else:
                        print(f"Warning: Non-dict or missing type item found in YAML proxies: {str(proxy)[:100]}")
            else: 
                if all(k in data for k in ['type', 'server', 'port']):
                     nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
                
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                elif isinstance(item, str):
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
        
        if nodes:
            print(f"Content parsed as YAML, found {len(nodes)} nodes.")
            return nodes
    except yaml.YAMLError as e:
        pass

    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                    else:
                        print(f"Warning: Non-dict or missing type item found in JSON proxies: {str(proxy)[:100]}")
            else:
                if all(k in data for k in ['type', 'server', 'port']):
                     nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                elif isinstance(item, str):
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
        
        if nodes:
            print(f"Content parsed as JSON, found {len(nodes)} nodes.")
            return nodes
    except json.JSONDecodeError as e:
        pass

    for i, line in enumerate(content.splitlines()):
        line_nodes = parse_line_as_node(line)
        if line_nodes:
            for node in line_nodes:
                nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
        else:
            if line.strip():
                print(f"Could not parse line {i+1} as a node: {line.strip()[:100]}...")

    return nodes

def get_output_filename(url: str) -> str:
    """根据 URL 路径确定输出文件名"""
    parsed_url = urlparse(url)
    path_segments = [s for s in parsed_url.path.split('/') if s]
    
    if path_segments:
        base_filename = path_segments[-1].split('.')[0] if '.' in path_segments[-1] else path_segments[-1]
        
        if "raw.githubusercontent.com" in parsed_url.hostname:
            repo_parts = [p for p in parsed_url.path.split('/') if p]
            if len(repo_parts) >= 3:
                user = repo_parts[0]
                repo = repo_parts[1]
                file_segment = repo_parts[-1].split('.')[0] if '.' in repo_parts[-1] else repo_parts[-1]
                
                filename = f"{user}_{repo}_{file_segment}"
                return re.sub(r'[^a-zA-Z0-9_.-]', '', filename) + ".yaml"

            elif base_filename:
                return base_filename.replace('~', '').replace('.', '_').replace('-', '_') + ".yaml"
        
        if base_filename:
            return base_filename.replace('~', '').replace('.', '_').replace('-', '_') + ".yaml"

    hostname_clean = parsed_url.hostname.replace('.', '_').replace('-', '_')
    if hostname_clean:
        return f"{hostname_clean}.yaml"
    
    return "default_nodes.yaml"

def save_nodes_to_yaml(nodes: List[Dict[str, Any]], output_filepath: str):
    """保存节点到 YAML 文件，处理重复名称并确保唯一性"""
    if not nodes:
        print(f"No valid nodes to save to {output_filepath}. Skipping file creation.")
        return
    
    processed_nodes: List[Dict[str, Any]] = []
    seen_names = defaultdict(int)

    for node in nodes:
        original_name = node.get('name', 'unknown_node')
        current_name = original_name
        
        # 如果名称已经存在，则添加递增的后缀
        # 注意：这里修改为只对原始名称进行计数，然后生成带后缀的唯一名称
        # 这样可以避免 "name #1 #2" 这种层叠的命名
        suffix_counter = 0
        while True:
            test_name = original_name
            if suffix_counter > 0:
                test_name = f"{original_name} #{suffix_counter}"
            
            if seen_names[test_name] == 0: # 如果这个带后缀的名称还没用过
                current_name = test_name
                break
            suffix_counter += 1
        
        node['name'] = current_name
        seen_names[current_name] += 1
        processed_nodes.append(node)

    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    
    yaml_data = {'proxies': processed_nodes}
    
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, indent=2, sort_keys=False)
        print(f"Successfully saved {len(processed_nodes)} unique nodes to {output_filepath}")
    except Exception as e:
        print(f"Error saving nodes to {output_filepath}: {e}")


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
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/data/all_unique_nodes.txt",
        "https://raw.githubusercontent.com/qjlxg/ha/refs/heads/main/merged_configs.txt",
        "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list_raw.txt",
        "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
    ]

    all_fetched_nodes: List[Dict[str, Any]] = [] # 新增：用于收集所有URL的节点

    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            # 修改 process_url 仅返回节点列表，不再单独保存文件
            # 这样可以在 main 函数中统一处理保存逻辑
            tasks.append(fetch_and_parse_nodes(session, url))
        
        results = await asyncio.gather(*tasks)
        for nodes_from_url in results:
            all_fetched_nodes.extend(nodes_from_url)
    
    # 新增：将所有收集到的节点保存到 all.yaml
    all_output_filepath = os.path.join('sc', 'all.yaml')
    save_nodes_to_yaml(all_fetched_nodes, all_output_filepath)


# 将原来的 process_url 拆分为两个函数：一个用于获取和解析，一个用于保存
async def fetch_and_parse_nodes(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """获取URL内容并解析为节点列表"""
    content = await fetch_url(session, url)
    if not content:
        print(f"No content fetched from {url}, returning empty list.")
        return []

    nodes = parse_content(content)
    
    # 额外：如果你仍然希望每个URL生成一个单独的yaml文件，可以在这里调用 save_nodes_to_yaml
    # 单独的 save_nodes_to_yaml 会进行各自的名称去重
    # output_filename = get_output_filename(url)
    # output_filepath = os.path.join('sc', output_filename)
    # save_nodes_to_yaml(nodes, output_filepath) # 注意：这里会再次对每个文件的节点进行名称去重
                                              # 如果你只需要一个 all.yaml，可以注释掉这部分

    return nodes


if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())
