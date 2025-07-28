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

# --- 全局配置开关 ---
# 将此设置为 True 启用区域过滤（排除国内节点和保留特定国际节点），
# 设置为 False 关闭区域过滤，所有通过其他校验的节点都会被保留。
ENABLE_REGION_FILTERING = False
# ---

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
                clean_content = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)

                # --- 添加内容预览以帮助调试 ---
                print("\n--- Fetched Content Preview (First 10 lines) ---")
                preview_lines = clean_content.splitlines()
                # If content is a single very long line, splitlines() will only have one element.
                # In that case, we print a snippet of that single line.
                if len(preview_lines) == 1 and len(preview_lines[0]) > 200:
                    print(f"Line 1 (snippet): {preview_lines[0][:200]}...")
                else:
                    for i, line in enumerate(preview_lines[:10]):
                        print(f"Line {i+1}: {line}")
                print("--- End Content Preview ---\n")
                # ---

                return clean_content
            else:
                print(f"Failed to fetch {url}: Status {response.status}", file=sys.stderr)
                return ""
    except Exception as e:
        print(f"Error fetching {url}: {str(e)}", file=sys.stderr)
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
    return node

def parse_vmess(data: str) -> Optional[Dict[str, Any]]:
    """解析 vmess 协议"""
    try:
        # Base64 decode, padding might be needed
        decoded_data_b64 = data.strip()
        decoded_data_b64 += '=' * (-len(decoded_data_b64) % 4) # Add padding
        decoded_data = base64.b64decode(decoded_data_b64).decode('utf-8')
        config = json.loads(decoded_data)
        
        server = config.get('add')
        port = int(config.get('port', 0))

        if not server or not port:
            print(f"Invalid vmess node: missing server or port in {decoded_data[:50]}...", file=sys.stderr)
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
        print(f"Error parsing vmess data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_trojan(data: str) -> Optional[Dict[str, Any]]:
    """解析 trojan 协议"""
    try:
        parsed_url = urlparse("trojan://" + data.strip())
        
        password = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('trojan', server, port)
        
        if not server or not port or not password:
            print(f"Invalid trojan node: missing server, port or password in {data[:50]}...", file=sys.stderr)
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
        parts = data.strip().split('#', 1)
        encoded_info = parts[0]
        
        decoded_info_b64 = encoded_info
        decoded_info_b64 += '=' * (-len(decoded_info_b64) % 4) # Add padding
        decoded_info = base64.b64decode(decoded_info_b64).decode('utf-8')
        
        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_info)
        if match:
            method, password, server, port_str = match.groups()
            port = int(port_str)
            node_name_from_fragment = unquote(parts[1]) if len(parts) > 1 else None
            
            if not server or not port or not method or not password:
                print(f"Invalid ss node: missing server, port, method or password in {decoded_info[:50]}...", file=sys.stderr)
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
        parsed_url = urlparse("vless://" + data.strip())
        
        uuid = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('vless', server, port)
        
        if not server or not port or not uuid:
            print(f"Invalid vless node: missing server, port or uuid in {data[:50]}...", file=sys.stderr)
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
            elif 'fingerprint' in params:
                node['fingerprint'] = params['fingerprint'][0] # Use fingerprint directly for VLESS as Clash supports it
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
        parsed_url = urlparse("hysteria2://" + data.strip())
        
        password = parsed_url.username if parsed_url.username else ""
        server = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('hysteria2', server, port)
        
        if not server or not port or not password:
            print(f"Invalid hysteria2 node: missing server, port or password in {data[:50]}...", file=sys.stderr)
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
        
        if 'short-id' in params:
            node['short-id'] = str(params['short-id'][0]) # 确保 short-id 是字符串
            
        return ensure_node_name(node, 'hysteria2')
    except Exception as e:
        print(f"Error parsing hysteria2 data '{data[:50]}...': {e}", file=sys.stderr)
        return None

def parse_ssr(data: str) -> Optional[Dict[str, Any]]:
    """解析 ssr 协议"""
    try:
        decoded_data_b64 = data.strip().replace('-', '+').replace('_', '/')
        decoded_data_b64 += '=' * (-len(decoded_data_b64) % 4) # Add padding
        decoded_data = base64.b64decode(decoded_data_b64).decode('utf-8')
        
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
            password_b64 = password_base64_part.replace('-', '+').replace('_', '/')
            password_b64 += '=' * (-len(password_b64) % 4) # Add padding
            password = base64.b64decode(password_b64).decode('utf-8')
        except Exception:
            password = ""

        params = {}
        if '/?' in password_encoded_and_params:
            query_string = password_encoded_and_params.split('/?')[1]
            params = parse_qs(query_string)
        
        name_encoded = params.get('remarks', [''])[0]
        name_b64 = name_encoded.replace('-', '+').replace('_', '/')
        name_b64 += '=' * (-len(name_b64) % 4) # Add padding
        node_name = unquote(base64.b64decode(name_b64).decode('utf-8')) if name_encoded else generate_node_name('ssr', server, port)
        
        obfs_param_encoded = params.get('obfsparam', [''])[0]
        obfs_param_b64 = obfs_param_encoded.replace('-', '+').replace('_', '/')
        obfs_param_b64 += '=' * (-len(obfs_param_b64) % 4) # Add padding
        obfs_param = unquote(base64.b64decode(obfs_param_b64).decode('utf-8')) if obfs_param_encoded else ''
        
        protocol_param_encoded = params.get('protoparam', [''])[0]
        protocol_param_b64 = protocol_param_encoded.replace('-', '+').replace('_', '/')
        protocol_param_b64 += '=' * (-len(protocol_param_b64) % 4) # Add padding
        protocol_param = unquote(base64.b64decode(protocol_param_b64).decode('utf-8')) if protocol_param_encoded else ''

        if not server or not port or not method or not password:
            print(f"Invalid ssr node: missing server, port, method or password in {decoded_data[:50]}...", file=sys.stderr)
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

    # Try direct protocol links
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
                    print(f"Skipping unparseable {protocol} node from line: {line[:100]}...", file=sys.stderr)
                return nodes # Return after first successful protocol match

    # Try multi-layer base64 decoding if no direct protocol match
    decoded_content = line
    for _ in range(5): # Try up to 5 times for multi-layer base64
        try:
            temp_decoded_b64 = decoded_content
            temp_decoded_b64 += '=' * (-len(temp_decoded_b64) % 4) # Add padding
            temp_decoded = base64.b64decode(temp_decoded_b64).decode('utf-8')
            
            # If the decoded content starts with any supported protocol, parse it
            for protocol in SUPPORTED_PROTOCOLS:
                if temp_decoded.startswith(f"{protocol}://"):
                    # Recursively call to handle potentially multiple links in a decoded string
                    nodes.extend(parse_line_as_node(temp_decoded))
                    return nodes
            decoded_content = temp_decoded # Continue decoding if not a direct protocol link
        except Exception:
            break
    
    return nodes

def parse_content(content: str) -> List[Dict[str, Any]]:
    """解析内容，可能包含多行节点、YAML 或 JSON"""
    nodes: List[Dict[str, Any]] = []
    
    # 移除控制字符：在获取内容后立即清理，防止后续解析出错
    content = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)

    # 1. 尝试作为完整的 YAML 加载
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            for proxy in data['proxies']:
                if isinstance(proxy, dict) and 'type' in proxy:
                    # 检查必要的字段，避免添加不完整的代理
                    if all(k in proxy for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                    else:
                        print(f"Warning: Skipping invalid YAML proxy (missing type, server or port): {str(proxy)[:100]}", file=sys.stderr)
                else:
                    print(f"Warning: Skipping non-dict or missing 'type' item found in YAML proxies: {str(proxy)[:100]}", file=sys.stderr)
            if nodes:
                print(f"Content parsed as YAML with 'proxies' key, found {len(nodes)} valid nodes.")
                return nodes
        elif isinstance(data, list):
            # 如果是 YAML 列表，尝试将每个元素作为节点
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    if all(k in item for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                    else:
                        print(f"Warning: Skipping invalid YAML list item (missing type, server or port): {str(item)[:100]}", file=sys.stderr)
                elif isinstance(item, str): # 尝试解析可能是节点链接的字符串
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
                else:
                    print(f"Warning: Skipping non-dict/non-str item in YAML list: {str(item)[:100]}", file=sys.stderr)
            if nodes:
                print(f"Content parsed as YAML list, found {len(nodes)} valid nodes.")
                return nodes
        elif isinstance(data, dict) and 'type' in data: # Single YAML node
            if all(k in data for k in ['type', 'server', 'port']):
                nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
                print(f"Content parsed as single YAML node, found 1 valid node.")
                return nodes
            else:
                print(f"Warning: Skipping invalid single YAML node (missing type, server or port): {str(data)[:100]}", file=sys.stderr)

    except yaml.YAMLError as e:
        print(f"Debug: Failed to parse as full YAML: {e}", file=sys.stderr)
        pass # Not a valid full YAML or not the expected structure, try next

    # 2. 尝试作为完整的 JSON 加载
    try:
        data = json.loads(content)
        if isinstance(data, dict) and 'proxies' in data and isinstance(data['proxies'], list):
            for proxy in data['proxies']:
                if isinstance(proxy, dict) and 'type' in proxy:
                    if all(k in proxy for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(proxy, proxy.get('type', 'unknown')))
                    else:
                        print(f"Warning: Skipping invalid JSON proxy (missing type, server or port): {str(proxy)[:100]}", file=sys.stderr)
                else:
                    print(f"Warning: Skipping non-dict or missing 'type' item found in JSON proxies: {str(proxy)[:100]}", file=sys.stderr)
            if nodes:
                print(f"Content parsed as JSON with 'proxies' key, found {len(nodes)} valid nodes.")
                return nodes
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'type' in item:
                    if all(k in item for k in ['type', 'server', 'port']):
                        nodes.append(ensure_node_name(item, item.get('type', 'unknown')))
                    else:
                        print(f"Warning: Skipping invalid JSON list item (missing type, server or port): {str(item)[:100]}", file=sys.stderr)
                elif isinstance(item, str): # 尝试解析可能是节点链接的字符串
                    parsed_from_line = parse_line_as_node(item)
                    for node in parsed_from_line:
                        nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
                else:
                    print(f"Warning: Skipping non-dict/non-str item in JSON list: {str(item)[:100]}", file=sys.stderr)
            if nodes:
                print(f"Content parsed as JSON list, found {len(nodes)} valid nodes.")
                return nodes
        elif isinstance(data, dict) and 'type' in data: # Single JSON node
            if all(k in data for k in ['type', 'server', 'port']):
                nodes.append(ensure_node_name(data, data.get('type', 'unknown')))
                print(f"Content parsed as single JSON node, found 1 valid node.")
                return nodes
            else:
                print(f"Warning: Skipping invalid single JSON node (missing type, server or port): {str(data)[:100]}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Debug: Failed to parse as full JSON: {e}", file=sys.stderr)
        pass # Not a valid full JSON, try next

    # --- 新增：处理被压扁的 YAML 内容 ---
    # 如果内容是单行且包含 'proxies:' 和 '- name:' 的模式，尝试按此模式分割
    if "\n" not in content and "proxies:- name:" in content:
        print("Attempting to parse content as a single-line (flattened) YAML-like string.")
        # 尝试通过正则表达式分割出每个代理的完整部分
        # 这个正则表达式尝试匹配从 '- name:' 开始到下一个 '- ' 或字符串末尾的部分
        # 注意：这是一种启发式方法，不保证100%准确，但能处理常见压扁格式
        # 针对您给出的预览，第一个 '- name:' 应该被 'proxies:' 包含
        # 我们寻找 ' - name:' 作为每个代理的开始
        raw_proxies = re.split(r' - name:', content)
        
        # 移除第一个元素（通常是 'proxies:' 或其之前的部分）
        if raw_proxies and raw_proxies[0].startswith('proxies:'):
            raw_proxies = raw_proxies[1:] # Skip the 'proxies:' part
        else: # Handle cases where 'proxies:' might not be at the very start or if it's just a list of items
             if raw_proxies:
                # If the first element doesn't start cleanly with 'name:', it might be part of the first item
                # Or it could be junk before the first actual item.
                # Let's try to infer if it's a valid first item or junk.
                if raw_proxies[0].strip().startswith('name:'):
                    pass # It's okay, the first element looks like a node
                else:
                    # If it's not a node, try to see if the content starts with 'proxies:'
                    # If it does, we assume the first part until the first '- name:' is junk
                    if content.strip().startswith('proxies:'):
                        # Find the first real '- name:' and take content from there
                        match_first_node_start = re.search(r' - name:', content)
                        if match_first_node_start:
                            content = content[match_first_node_start.start() + 1:].strip()
                            raw_proxies = re.split(r' - name:', content) # Resplit from the cleaned content
                    
                    if raw_proxies and not raw_proxies[0].strip().startswith('name:'):
                         # If after all attempts the first element still doesn't look like 'name:', it's likely junk
                         raw_proxies = raw_proxies[1:] # Remove it as junk
        
        for i, item_str_raw in enumerate(raw_proxies):
            item_str = item_str_raw.strip()
            if not item_str:
                continue

            # Reconstruct as a valid YAML block for safe_load.
            # Replace spaces after colon with a single space to avoid multiple spaces breaking YAML
            # Add a name prefix back for the first item
            if not item_str.startswith('name:'):
                 item_str = 'name:' + item_str

            # Now, try to make it a valid YAML string with proper indentation for a single item
            # Replace multiple spaces after ':' with a single space if it's a key-value pair
            clean_item_str = re.sub(r'([a-zA-Z0-9_-]+):(\s+)', r'\1: ', item_str)
            
            # For properties that might be concatenated, like 'type:trojan-sni:example.com', convert to standard YAML
            # This is hard to do reliably with regex alone.
            # The best approach is to re-parse each fragment as a standalone YAML dict.
            
            # Convert single-line "key: value key2: value2" to multi-line "key: value\nkey2: value2"
            # This is still very challenging for a general solution without full YAML parser.
            # A more robust approach:
            
            # Let's try to convert `key:val key2:val2` to `key: val\nkey2: val2`
            # This is still a heuristic.
            
            # Simple heuristic: Split by spaces, then rejoin if it's not a 'key:'
            # This is likely to fail given the complexity.
            # The most reliable way for flattened YAML is to assume it's a list of dicts.
            # We'll try to reconstruct each segment into a dictionary.

            # We need to treat each 'name: ... ' as a starting point of a node.
            # The structure appears to be `key:value key2:value2 key3:value3`
            
            # Reconstruct as a valid YAML dictionary string
            # This is highly dependent on the exact structure of the "flattened" YAML.
            # Based on the provided example, each entry seems to be a list of `key: value` pairs separated by spaces.
            
            # Let's try to convert it into a proper YAML dictionary string for each segment
            # e.g., "name: foo password: bar" => "name: foo\n  password: bar"
            
            yaml_format_item = ""
            parts = re.findall(r'(\w+:\s*[^ ]+)', item_str) # Find key:value pairs, roughly
            if not parts:
                 parts = re.findall(r'(\w+:[^ ]+)', item_str) # Try without space after colon

            if parts:
                yaml_format_item += "  " + "\n  ".join(parts) # Indent each part
                try:
                    single_node = yaml.safe_load(yaml_format_item)
                    if isinstance(single_node, dict) and 'type' in single_node:
                        # Correct "type" and ensure "name"
                        nodes.append(ensure_node_name(single_node, single_node.get('type', 'unknown')))
                    else:
                        print(f"Warning: Skipping malformed flattened YAML segment (not a dict or missing type) {i+1}: '{item_str[:100]}...'", file=sys.stderr)
                except yaml.YAMLError as e:
                    print(f"Warning: Failed to parse flattened YAML segment {i+1} as YAML: {e} - '{item_str[:100]}...'", file=sys.stderr)
                except Exception as e:
                    print(f"Error processing flattened YAML segment {i+1}: {e} - '{item_str[:100]}...'", file=sys.stderr)
            else:
                 print(f"Warning: Could not extract key-value pairs from flattened YAML segment {i+1}: '{item_str[:100]}...'", file=sys.stderr)

        if nodes:
            print(f"Content parsed as flattened YAML, found {len(nodes)} valid nodes.")
            return nodes
    # --- 结束处理被压扁的 YAML 内容 ---


    # 3. 如果以上失败，则逐行解析（用于 vmess:// 等格式）
    # This block will still catch standard base64 encoded links or direct protocol links
    print("Content is neither valid full YAML nor JSON, attempting line-by-line parsing for individual node links.")
    for i, line in enumerate(content.splitlines()):
        line_nodes = parse_line_as_node(line)
        if line_nodes:
            for node in line_nodes:
                nodes.append(ensure_node_name(node, node.get('type', 'unknown')))
        else:
            if line.strip(): # Only print warning for non-empty lines
                print(f"Warning: Could not parse line {i+1} as a node: {line.strip()[:100]}...", file=sys.stderr)

    if not nodes:
        print("Warning: No nodes found after attempting all parsing methods.", file=sys.stderr)
    return nodes

def filter_nodes(proxies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    根据给定的规则过滤代理节点：
    - 校验必填字段
    - 校验特定协议的特殊字段（如 VMess cipher, VLESS security, SS cipher, SSR obfs-param）
    - 可选的区域过滤
    """
    filtered_proxies = []
    
    for i, proxy in enumerate(proxies):
        # --- 确保代理是字典类型且包含 'type' 字段 ---
        if not isinstance(proxy, dict) or 'type' not in proxy:
            print(f"Warning: Proxy {i+1}: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else str(proxy)[:50]}...", file=sys.stderr)
            continue

        proxy_type = proxy['type']
        original_proxy_name = proxy.get('name', f"Unnamed Proxy {i+1}")
        proxy_name = original_proxy_name # 初始化为原始名称

        is_valid_node = True
        missing_fields = []

        # --- 增强的 VMess 错误排除：针对 unsupported security type 和 cipher missing ---
        if proxy_type == 'vmess':
            valid_vmess_ciphers = [
                'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305',
                'chacha20-ietf-poly1305', 'aes-256-gcm'
            ]
            
            vmess_cipher = proxy.get('cipher')

            if vmess_cipher is None:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy because 'cipher' field is missing. This often causes 'key 'cipher' missing' error.", file=sys.stderr)
                is_valid_node = False
            elif not isinstance(vmess_cipher, str) or vmess_cipher.strip() == '':
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to invalid or empty 'cipher' field (received: '{vmess_cipher}'). This incessantly causes 'unsupported security type' error.", file=sys.stderr)
                is_valid_node = False
            elif vmess_cipher.lower() not in valid_vmess_ciphers:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to unsupported 'cipher' type ('{vmess_cipher}'). This often causes 'unsupported security type' error.", file=sys.stderr)
                is_valid_node = False

        # --- 针对不同代理类型校验所需的关键字段是否存在 ---
        if proxy_type == 'vmess':
            required_fields = ['server', 'port', 'uuid', 'alterId']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
        elif proxy_type == 'trojan':
            required_fields = ['server', 'port', 'password']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
        elif proxy_type == 'ss':
            required_fields = ['server', 'port', 'cipher', 'password']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
            # 特殊处理：排除 cipher 为 'ss' 的 SS 节点
            if proxy.get('cipher') is None or (isinstance(proxy.get('cipher'), str) and proxy.get('cipher').lower() == 'ss'):
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SS proxy due to missing or unsupported 'cipher' method ('{proxy.get('cipher', 'missing') if proxy.get('cipher') is not None else 'missing'}').", file=sys.stderr)
                is_valid_node = False

        elif proxy_type == 'vless':
            required_fields = ['server', 'port', 'uuid']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
            vless_security = proxy.get('security')
            if vless_security is not None:
                if not isinstance(vless_security, str) or \
                   (isinstance(vless_security, str) and vless_security.strip() == '') or \
                   (vless_security.lower() not in ['tls', 'none']):
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VLESS proxy due to unsupported or empty 'security' field ('{vless_security}').", file=sys.stderr)
                    is_valid_node = False
        elif proxy_type == 'hysteria2':
            required_fields = ['server', 'port', 'password']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
        elif proxy_type == 'ssr':
            required_fields = ['server', 'port', 'cipher', 'password', 'protocol', 'obfs']
            for field in required_fields:
                if field not in proxy:
                    missing_fields.append(field)
            if missing_fields:
                is_valid_node = False
            if proxy.get('cipher') is None:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy due to missing 'cipher' field.", file=sys.stderr)
                is_valid_node = False
            # --- 新增：SSR obfs-param 校验 ---
            # 如果 obfs 字段存在，则 obfs-param 不能为空或缺失
            if 'obfs' in proxy and proxy['obfs'] is not None and proxy['obfs'].strip() != '':
                if 'obfs-param' not in proxy or proxy['obfs-param'] is None or proxy['obfs-param'].strip() == '':
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy because 'obfs' is specified but 'obfs-param' is missing or empty. This causes 'missing obfs password' or similar errors.", file=sys.stderr)
                    is_valid_node = False
            # --- SSR obfs-param 校验结束 ---
        else:
            # 警告并跳过不支持的代理类型
            print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping unsupported proxy type '{proxy_type}'.", file=sys.stderr)
            continue


        # 如果节点在上述校验中被标记为无效，则跳过
        if not is_valid_node:
            if missing_fields:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy due to missing required fields: {', '.join(missing_fields)}.", file=sys.stderr)
            continue

        # 确保 'server' 或 'host' 字段存在以获取服务器地址，这是后续判断的基础
        server_address = proxy.get('server')
        if not server_address:
            server_address = proxy.get('host')
        
        if not server_address:
            print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it has no 'server' or 'host' key (secondary check).", file=sys.stderr)
            continue

        # --- 区域过滤逻辑 (根据 ENABLE_REGION_FILTERING 开关控制) ---
        if ENABLE_REGION_FILTERING:
            # 定义要排除的国内地区关键词（中文和拼音），以及常见的国内云服务商
            keywords_to_exclude = [
                'cn', 'china', '中国', '大陆', 'tencent', 'aliyun', '华为云', '移动', '联通', '电信', # 省份
                '北京', '上海', '广东', '江苏', '浙江', '四川', '重庆', '湖北', '湖南', '福建', '山东',
                '河南', '河北', '山西', '陕西', '辽宁', '吉林', '黑龙江', '安徽', '江西', '广西', '云南',
                '贵州', '甘肃', '青海', '宁夏', '新疆', '西藏', '内蒙古', '天津', '海南', 'hk', 'tw', 'mo' # 港澳台也算排除
            ]
            
            is_domestic_node = False
            # 检查服务器地址是否包含排除关键词
            for keyword in keywords_to_exclude:
                if keyword.lower() in server_address.lower():
                    is_domestic_node = True
                    break
            
            # 如果服务器地址未匹配到，则检查节点名称是否包含排除关键词
            if not is_domestic_node:
                for keyword in keywords_to_exclude:
                    if keyword.lower() in proxy_name.lower():
                        is_domestic_node = True
                        break

            if is_domestic_node:
                print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it appears to be a domestic Chinese node or a region often considered domestic by VPN users (HK/TW/MO for some policies). Server/Host: {server_address}", file=sys.stderr)
                continue # 跳过此代理


            # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称 (这些是您希望保留的国际节点)
            keywords_to_keep_near_china = ['sg', 'jp', 'kr', 'ru'] 

            matched_region_to_keep = False
            # 检查服务器地址是否包含保留关键词
            for keyword in keywords_to_keep_near_china:
                if keyword.lower() in server_address.lower():
                    matched_region_to_keep = True
                    break
            
            # 如果服务器地址未匹配到，则检查节点名称是否包含保留关键词
            if not matched_region_to_keep:
                for keyword in keywords_to_keep_near_china:
                    if keyword.lower() in proxy_name.lower():
                        matched_region_to_keep = True
                        break

            # 如果开启了过滤，但节点不属于要保留的区域，则跳过
            if not matched_region_to_keep: 
                print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it does not match close-to-China international regions. Server/Host: {server_address}", file=sys.stderr)
                continue # 跳过此代理
        # --- 区域过滤逻辑结束 ---

        # 确保 short-id 是字符串类型，以防在 YAML 导出时被误解析为数字
        if 'short-id' in proxy and not isinstance(proxy['short-id'], str):
            proxy['short-id'] = str(proxy['short-id'])

        # 处理 'tls' 字段的类型转换 (字符串 "true" / "false" 到布尔值)
        if 'tls' in proxy:
            tls_value = proxy['tls']
            if isinstance(tls_value, str):
                proxy['tls'] = tls_value.lower() == 'true'
            elif not isinstance(tls_value, bool):
                proxy['tls'] = False # 如果不是字符串也不是布尔值，则设为 False

        # 如果通过所有检查（包括可选的区域过滤），则添加到过滤列表中
        filtered_proxies.append(proxy) 
    
    # 在所有节点都被处理并添加到 filtered_proxies 之后，再进行名称唯一化
    final_unique_proxies = []
    seen_names_for_final = defaultdict(int)

    for proxy in filtered_proxies:
        original_name = proxy.get('name', 'unknown_node')
        current_name = original_name
        
        suffix_counter = 0
        while True:
            test_name = original_name
            if suffix_counter > 0:
                test_name = f"{original_name} #{suffix_counter}"
            
            # 检查去重后的新名称是否已被使用
            if seen_names_for_final[test_name] == 0:
                current_name = test_name
                break
            suffix_counter += 1
        
        # 只有在名称确实改变时才更新
        if proxy.get('name') != current_name:
             print(f"Info: Renaming duplicate node '{proxy.get('name')}' to '{current_name}'.", file=sys.stderr)
        proxy['name'] = current_name
        seen_names_for_final[current_name] += 1
        final_unique_proxies.append(proxy)

    print(f"Filtered down to {len(final_unique_proxies)} unique and valid nodes.")
    return final_unique_proxies


def get_output_filename(url: str) -> str:
    """根据 URL 路径确定输出文件名"""
    parsed_url = urlparse(url)
    path_segments = [s for s in parsed_url.path.split('/') if s]
    
    # 更智能地处理文件名，尤其是针对 GitHub raw content
    if "raw.githubusercontent.com" in parsed_url.hostname:
        if len(path_segments) >= 4: # e.g., user/repo/branch/path/to/file.ext
            user = path_segments[0]
            repo = path_segments[1]
            # Get the actual filename part, without branch or extra path segments
            filename_with_ext = path_segments[-1]
            base_filename = os.path.splitext(filename_with_ext)[0]
            
            # Use the last part of the path as the primary name, or a combination if needed
            if base_filename == "clash" and repo == "aggregator":
                return "aggregator_clash.yaml"
            elif base_filename == "configtg" and repo == "hy2":
                return "hy2_configtg.yaml"
            elif base_filename == "config_all_merged_nodes" and repo == "collectSub":
                return "collectSub_all_merged_nodes.yaml"
            elif base_filename == "all" and repo == "my": # Your problematic URL
                return "my_all_nodes.yaml"
            else:
                # Default for other github raw content
                return f"{user}_{repo}_{base_filename}.yaml"
        elif path_segments: # Simpler github raw path
            return path_segments[-1].replace('.', '_').replace('-', '_') + ".yaml"
    
    # For other URLs, use the last segment or hostname
    if path_segments:
        base_filename = os.path.splitext(path_segments[-1])[0]
        if base_filename:
            return base_filename.replace('~', '').replace('.', '_').replace('-', '_') + ".yaml"

    hostname_clean = parsed_url.hostname.replace('.', '_').replace('-', '_')
    if hostname_clean:
        return f"{hostname_clean}.yaml"
    
    return "default_nodes.yaml"

def save_nodes_to_yaml(nodes: List[Dict[str, Any]], output_filepath: str):
    """保存节点到 YAML 文件"""
    if not nodes:
        print(f"No valid nodes to save to {output_filepath}. Skipping file creation.")
        return
    
    # 确保 short-id 是字符串类型
    for node in nodes:
        if 'short-id' in node and not isinstance(node['short-id'], str):
            node['short-id'] = str(node['short-id']) 

    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    
    yaml_data = {'proxies': nodes}
    
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, indent=2, sort_keys=False) 
        print(f"Successfully saved {len(nodes)} unique nodes to {output_filepath}")
    except Exception as e:
        print(f"Error saving nodes to {output_filepath}: {e}", file=sys.stderr)

async def main():
    urls = [
        "https://raw.githubusercontent.com/qjlxg/my/refs/heads/main/sc/all.yaml",
        "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
        "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
    ]

    all_fetched_nodes: List[Dict[str, Any]] = []

    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            tasks.append(fetch_and_parse_nodes(session, url))
        
        results = await asyncio.gather(*tasks)
        for nodes_from_url in results:
            all_fetched_nodes.extend(nodes_from_url)
    
    print(f"\nTotal nodes fetched before filtering: {len(all_fetched_nodes)}")
    
    # --- 应用过滤逻辑 ---
    filtered_and_unique_nodes = filter_nodes(all_fetched_nodes)
    
    # 将所有过滤后的节点保存到一个统一的 all.yaml 文件中
    all_output_filepath = os.path.join('sc', 'all.yaml')
    save_nodes_to_yaml(filtered_and_unique_nodes, all_output_filepath)


async def fetch_and_parse_nodes(session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
    """获取URL内容并解析为节点列表"""
    content = await fetch_url(session, url)
    if not content:
        print(f"No content fetched from {url}, returning empty list.")
        return []

    # 为每个 URL 生成不同的输出文件名，但最终会合并到 all.yaml
    # filename_for_this_url = get_output_filename(url)
    # individual_output_filepath = os.path.join('sc', filename_for_this_url)
    
    nodes = parse_content(content)
    # save_nodes_to_yaml(nodes, individual_output_filepath) # 暂时不保存单个文件的节点，只合并
    return nodes


if __name__ == "__main__":
    if platform.system() == "Emscripten":
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())
