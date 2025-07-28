import aiohttp
import asyncio
import base64
import json
import yaml
import os
import re
import platform
import sys
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
                content = await response.text()
                # 1. 移除控制字符：在获取内容后立即清理，防止后续解析出错
                return re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)
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
        # 移除任何可能的空白字符，特别是对于 base64 编码的字符串
        decoded_data = base64.b64decode(data.strip() + '==').decode('utf-8')
        config = json.loads(decoded_data)
        
        server = config.get('add')
        port = int(config.get('port', 0))

        # 3. 过滤无效或非标准的代理节点：添加基本校验
        if not server or not port:
            print(f"Invalid vmess node: missing server or port in {decoded_data[:50]}...")
            return None

        uuid = config.get('id', "")
        alter_id = int(config.get('aid', 0))
        
        cipher = config.get('type') 
        if not cipher or not isinstance(cipher, str) or cipher.strip() == '':
            cipher = 'auto'

        node = {
            'name': config.get('ps', generate_node_name('vmess', server, port)),
            'type': 'vmess',
            'server': server,
            'port': port,
            'uuid': uuid,
            'alterId': alter_id,
            'cipher': cipher 
        }

        if config.get('tls') == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = bool(config.get('scy', False))
            if 'host' in config and config['host']:
                node['sni'] = config['host']
            
            if 'fp' in config and config['fp']:
                node['client-fingerprint'] = config['fp']
            elif 'fingerprint' in config and config['fingerprint']: # 兼容不同的字段名
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
        print(f"Error parsing vmess data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_trojan(data: str) -> Optional[Dict[str, Any]]:
    """解析 trojan 协议"""
    try:
        parsed_url = urlparse("trojan://" + data.strip()) # 移除空白字符
        
        password = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('trojan', server, port)
        
        # 3. 过滤无效或非标准的代理节点：添加基本校验
        if not server or not port or not password:
            print(f"Invalid trojan node: missing server, port or password in {data[:50]}...")
            return None

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
        print(f"Error parsing trojan data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_ss(data: str) -> Optional[Dict[str, Any]]:
    """解析 ss 协议"""
    try:
        parts = data.strip().split('#', 1) # 移除空白字符
        encoded_info = parts[0]
        
        decoded_info = base64.b64decode(encoded_info + '==').decode('utf-8')
        
        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_info)
        if match:
            method, password, server, port_str = match.groups()
            port = int(port_str)
            node_name_from_fragment = unquote(parts[1]) if len(parts) > 1 else None
            
            # 3. 过滤无效或非标准的代理节点：添加基本校验
            if not server or not port or not method or not password:
                print(f"Invalid ss node: missing server, port, method or password in {decoded_info[:50]}...")
                return None

            method = method if method else 'auto' 

            node = {
                'name': node_name_from_fragment if node_name_from_fragment else generate_node_name('ss', server, port),
                'type': 'ss',
                'server': server,
                'port': port,
                'cipher': method, 
                'password': password if password else "",
            }
            return ensure_node_name(node, 'ss')
        else:
            print(f"SS data format not recognized: {decoded_info[:50]}...", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error parsing ss data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_vless(data: str) -> Optional[Dict[str, Any]]:
    """解析 vless 协议"""
    try:
        parsed_url = urlparse("vless://" + data.strip()) # 移除空白字符
        
        uuid = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('vless', server, port)
        
        # 3. 过滤无效或非标准的代理节点：添加基本校验
        if not server or not port or not uuid:
            print(f"Invalid vless node: missing server, port or uuid in {data[:50]}...")
            return None

        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid
        }

        security_param = params.get('security', [''])[0]
        if security_param == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = (params.get('allowInsecure', ['0'])[0] == '1')
            if 'sni' in params:
                node['sni'] = params['sni'][0]
            
            if 'fp' in params:
                node['client-fingerprint'] = params['fp'][0]
            elif 'fingerprint' in params: # 兼容不同的字段名
                node['client-fingerprint'] = params['fingerprint'][0]
        elif security_param and security_param != 'none':
            print(f"Warning: Vless node '{name}' has unknown security type: '{security_param}'", file=sys.stderr)


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
        print(f"Error parsing vless data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_hysteria2(data: str) -> Optional[Dict[str, Any]]:
    """解析 hysteria2 协议"""
    try:
        parsed_url = urlparse("hysteria2://" + data.strip()) # 移除空白字符
        
        password = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('hysteria2', server, port)
        
        # 3. 过滤无效或非标准的代理节点：添加基本校验
        if not server or not port or not password:
            print(f"Invalid hysteria2 node: missing server, port or password in {data[:50]}...")
            return None

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
        # 2. 强制为 short-id 添加引号：Hysteria2 协议可能包含 short-id
        if 'short-id' in params:
            node['short-id'] = str(params['short-id'][0]) # 强制转换为字符串
            
        return ensure_node_name(node, 'hysteria2')
    except Exception as e:
        print(f"Error parsing hysteria2 data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_ssr(data: str) -> Optional[Dict[str, Any]]:
    """解析 ssr 协议"""
    try:
        # SSR 的 base64 编码通常需要特殊处理填充和字符替换
        decoded_data = base64.b64decode(data.strip().replace('-', '+').replace('_', '/') + '==').decode('utf-8')
        
        parts = decoded_data.split(':')
        if len(parts) < 6:
            print(f"SSR data has too few parts: {decoded_data[:50]}...", file=sys.stderr)
            return None

        server = parts[0]
        port = int(parts[1])
        protocol_type = parts[2]
        method = parts[3]
        obfs = parts[4]
        
        password_encoded_and_params = parts[5]
        password_base64_part = password_encoded_and_params.split('/?')[0]
        
        try:
            password = base64.b64decode(password_base64_part.replace('-', '+').replace('_', '/') + '==').decode('utf-8')
        except Exception:
            password = ""

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

        # 3. 过滤无效或非标准的代理节点：添加基本校验
        if not server or not port or not method or not password:
            print(f"Invalid ssr node: missing server, port, method or password in {decoded_data[:50]}...")
            return None

        method = method if method else 'auto' 

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
        print(f"Error parsing ssr data '{data[:50]}...': {e}", file=sys.stderr)
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
                    # 3. 过滤无效或非标准的代理节点：这里已经有打印，但可以更明确
                    print(f"Skipping unparseable {protocol} node from line: {line[:100]}...", file=sys.stderr)
            return nodes

    decoded_content = line
    for _ in range(5): # 尝试多层 base64 解码
        try:
            temp_decoded = base64.b64decode(decoded_content + '==').decode('utf-8')
            for protocol in SUPPORTED_PROTOCOLS:
                if temp_decoded.startswith(f"{protocol}://"):
                    nodes.extend(parse_line_as_node(temp_decoded))
                    return nodes
            decoded_content = temp_decoded
        except Exception:
            break
    
    # 如果经过多次尝试仍未能解析，可能是无效行
    # print(f"Could not parse line after multiple decodings: {line[:100]}...", file=sys.stderr)
    return nodes

def parse_content(content: str) -> List[Dict[str, Any]]:
    """解析内容，可能包含多行节点、YAML 或 JSON"""
    nodes: List[Dict[str, Any]] = []
    
    # 1. 移除控制字符：在解析内容之前进行一次全局清理
    content = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)

    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        # 3. 过滤无效或非标准的代理节点：对从 YAML/JSON 加载的节点也进行基本校验
                        if all(k in proxy for k in ['type', 'server', 'port']):
                            nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                        else:
                            print(f"Skipping invalid YAML proxy (missing type, server or port): {str(proxy)[:100]}", file=sys.stderr)
                    else:
                        print(f"Skipping non-dict or missing type item found in YAML proxies: {str(proxy)[:100]}", file=sys.stderr)
            else: 
                # 处理单个 YAML 节点的情况，例如 'type: vmess' 这种
                if all(k in data for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
                else:
                    print(f"Skipping invalid single YAML node (missing type, server or port): {str(data)[:100]}", file=sys.stderr)
                
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    # 3. 过滤无效或非标准的代理节点：对从 YAML/JSON 加载的节点也进行基本校验
                    if all(k in item for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                    else:
                        print(f"Skipping invalid YAML list item (missing type, server or port): {str(item)[:100]}", file=sys.stderr)
                elif isinstance(item, str):
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
                else:
                    print(f"Skipping non-dict/non-str item in YAML list: {str(item)[:100]}", file=sys.stderr)
        
        if nodes:
            print(f"Content parsed as YAML, found {len(nodes)} valid nodes.")
            return nodes
    except yaml.YAMLError:
        pass # 不是 YAML，继续尝试 JSON

    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                for proxy in data['proxies']:
                    if isinstance(proxy, dict) and 'type' in proxy:
                        # 3. 过滤无效或非标准的代理节点：对从 YAML/JSON 加载的节点也进行基本校验
                        if all(k in proxy for k in ['type', 'server', 'port']):
                            nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                        else:
                            print(f"Skipping invalid JSON proxy (missing type, server or port): {str(proxy)[:100]}", file=sys.stderr)
                    else:
                        print(f"Skipping non-dict or missing type item found in JSON proxies: {str(proxy)[:100]}", file=sys.stderr)
            else:
                # 处理单个 JSON 节点的情况
                if all(k in data for k in ['type', 'server', 'port']):
                    nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
                else:
                    print(f"Skipping invalid single JSON node (missing type, server or port): {str(data)[:100]}", file=sys.stderr)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    # 3. 过滤无效或非标准的代理节点：对从 YAML/JSON 加载的节点也进行基本校验
                    if all(k in item for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                    else:
                        print(f"Skipping invalid JSON list item (missing type, server or port): {str(item)[:100]}", file=sys.stderr)
                elif isinstance(item, str):
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
                else:
                    print(f"Skipping non-dict/non-str item in JSON list: {str(item)[:100]}", file=sys.stderr)
        
        if nodes:
            print(f"Content parsed as JSON, found {len(nodes)} valid nodes.")
            return nodes
    except json.JSONDecodeError:
        pass # 不是 JSON，继续尝试按行解析

    # 如果既不是 YAML 也不是 JSON，则尝试按行解析原始文本内容
    print("Content is neither valid YAML nor JSON, attempting line-by-line parsing.")
    for i, line in enumerate(content.splitlines()):
        line_nodes = parse_line_as_node(line)
        if line_nodes:
            for node in line_nodes:
                nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
        else:
            if line.strip(): # 只打印非空行的解析失败信息
                print(f"Could not parse line {i+1} as a node: {line.strip()[:100]}...", file=sys.stderr)

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
        
        suffix_counter = 0
        current_name = original_name
        while True:
            test_name = original_name
            if suffix_counter > 0:
                test_name = f"{original_name} #{suffix_counter}"
            
            # 确保生成的名称在已处理节点中是唯一的
            if test_name not in seen_names:
                current_name = test_name
                break
            suffix_counter += 1
        
        node['name'] = current_name
        seen_names[current_name] += 1
        processed_nodes.append(node)

    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    
    yaml_data = {'proxies': processed_nodes}
    
    # 定义 YAML 自定义 Dumper
    # 2. 强制为 short-id 添加引号：通过自定义 representer 确保 short-id 被引用
    class QuotingSafeDumper(yaml.SafeDumper):
        def represent_scalar(self, tag, value, style=None):
            if tag == 'tag:yaml.org,2002:str' and value.isdigit() and len(value) < 10: # 示例：短数字字符串
                # 检查是否为 'short-id' 字段的值，如果是，强制使用引号
                # 这个检查需要上下文信息，例如在 represent_mapping 或其他地方
                # 对于通用 scalar，我们只能根据值本身判断是否需要引号
                # 更精确的控制可能需要修改上层逻辑，在构建节点字典时就将 short-id 转为字符串类型
                # 或者在保存时，检查 key 是否是 short-id，然后特殊处理 value。
                # 由于 YAML 的 representer 是通用的，这里为了演示，可以假设如果一个数字字符串可能被误解析，就引用它。
                if 'short-id' in self.ancestor_keys and isinstance(value, str): # 这是一个假设的检查
                    return super().represent_scalar(tag, value, style='\'')
            return super().represent_scalar(tag, value, style=style)

    # 尝试更直接的控制 short-id 引用，确保它是字符串类型
    for node in processed_nodes:
        if 'short-id' in node and not isinstance(node['short-id'], str):
            node['short-id'] = str(node['short-id']) # 确保 short-id 是字符串

    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            # 移除 QuotingSafeDumper，因为直接在节点处理时将其转换为字符串更可靠
            yaml.dump(yaml_data, f, allow_unicode=True, indent=2, sort_keys=False) 
        print(f"Successfully saved {len(processed_nodes)} unique nodes to {output_filepath}")
    except Exception as e:
        print(f"Error saving nodes to {output_filepath}: {e}", file=sys.stderr)

async def main():
    urls = [
        "https://raw.githubusercontent.com/qjlxg/ss/refs/heads/master/list.meta.yml",
        # 您可以在此处添加更多 URL
        # "https://example.com/some_other_sub.txt",
        # "https://example.com/another_yaml_sub.yaml"
    ]

    all_fetched_nodes: List[Dict[str, Any]] = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            tasks.append(fetch_and_parse_nodes(session, url))
        
        results = await asyncio.gather(*tasks)
        for nodes_from_url in results:
            all_fetched_nodes.extend(nodes_from_url)
    
    all_output_filepath = os.path.join('sc', 'all.yaml')
    save_nodes_to_yaml(all_fetched_nodes, all_output_filepath)


async def fetch_and_parse_nodes(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """获取URL内容并解析为节点列表"""
    content = await fetch_url(session, url)
    if not content:
        print(f"No content fetched from {url}, returning empty list.")
        return []

    nodes = parse_content(content)
    return nodes


if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())
