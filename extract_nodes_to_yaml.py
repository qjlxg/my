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

def generate_node_name(protocol: str, server: str, port: int) -> str:
    """生成默认节点名称"""
    return f"{protocol}-{server}:{port}"

def parse_vmess(data: str) -> Optional[Dict[str, Any]]:
    """解析 vmess 协议"""
    try:
        decoded_data = base64.b64decode(data + '==').decode('utf-8') # Add padding
        config = json.loads(decoded_data)
        
        node = {
            'name': config.get('ps', generate_node_name('vmess', config.get('add', ''), config.get('port', ''))),
            'type': 'vmess',
            'server': config.get('add'),
            'port': int(config.get('port')),
            'uuid': config.get('id'),
            'alterId': int(config.get('aid', 0)),
            'cipher': 'auto'
        }

        # TLS settings
        if config.get('tls') == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = bool(config.get('scy', False))
            if 'sni' in config: # vmess often uses host for SNI
                node['sni'] = config['host']
        
        # Network settings
        network = config.get('net')
        if network:
            node['network'] = network
            if network == 'ws':
                node['ws-path'] = config.get('path', '/')
                if 'host' in config and config['host']:
                    node['ws-headers'] = {'Host': config['host']}
            elif network == 'grpc':
                node['grpc-service-name'] = config.get('path', '') # vmess uses path for serviceName
        
        return node
    except Exception as e:
        print(f"Error parsing vmess data '{data[:50]}...': {e}")
        return None

def parse_trojan(data: str) -> Optional[Dict[str, Any]]:
    """解析 trojan 协议"""
    try:
        # trojan://password@server:port?params#name
        parsed_url = urlparse("trojan://" + data)
        
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('trojan', server, port)
        
        # Parse query parameters
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port or 443,
            'password': password,
            'tls': True # Trojan always uses TLS
        }
        
        # TLS specific parameters
        node['skip-cert-verify'] = (params.get('allowInsecure', ['0'])[0] == '1')
        if 'sni' in params:
            node['sni'] = params['sni'][0]
        if 'fp' in params: # Fingerprint
            node['fingerprint'] = params['fp'][0]
        if 'alpn' in params:
            node['alpn'] = params['alpn'][0].split(',')

        return node
    except Exception as e:
        print(f"Error parsing trojan data '{data[:50]}...': {e}")
        return None

def parse_ss(data: str) -> Optional[Dict[str, Any]]:
    """解析 ss 协议"""
    try:
        # SS links usually are base64(method:password@server:port)#name or base64(method:password@server:port)
        # Handle the base64 part first
        parts = data.split('#', 1)
        encoded_info = parts[0]
        node_name = unquote(parts[1]) if len(parts) > 1 else 'shadowsocks_node'

        decoded_info = base64.b64decode(encoded_info + '==').decode('utf-8') # Add padding
        
        # Try to parse method:password@server:port
        match = re.match(r'(.+?):(.+?)@(.+?):(\d+)', decoded_info)
        if match:
            method, password, server, port = match.groups()
            node = {
                'name': node_name if node_name != 'shadowsocks_node' else generate_node_name('ss', server, port),
                'type': 'ss',
                'server': server,
                'port': int(port),
                'cipher': method,
                'password': password
            }
            return node
        else:
            print(f"SS data format not recognized: {decoded_info[:50]}...")
            return None
    except Exception as e:
        print(f"Error parsing ss data '{data[:50]}...': {e}")
        return None

def parse_vless(data: str) -> Optional[Dict[str, Any]]:
    """解析 vless 协议"""
    try:
        # vless://uuid@server:port?params#name
        parsed_url = urlparse("vless://" + data)
        
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('vless', server, port)
        
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port or 443,
            'uuid': uuid
        }

        # TLS settings
        if params.get('security', [''])[0] == 'tls':
            node['tls'] = True
            node['skip-cert-verify'] = (params.get('allowInsecure', ['0'])[0] == '1')
            if 'sni' in params:
                node['sni'] = params['sni'][0]
            if 'fp' in params:
                node['fingerprint'] = params['fp'][0]
        
        # Network settings
        network = params.get('type', [''])[0]
        if network:
            node['network'] = network
            if network == 'ws':
                node['ws-path'] = params.get('path', ['/'])[0]
                if 'host' in params and params['host'][0]:
                    node['ws-headers'] = {'Host': params['host'][0]}
            elif network == 'grpc':
                node['grpc-service-name'] = params.get('serviceName', [''])[0]
        
        # XTLS/Reality flow
        if 'flow' in params:
            node['flow'] = params['flow'][0]

        return node
    except Exception as e:
        print(f"Error parsing vless data '{data[:50]}...': {e}")
        return None

def parse_hysteria2(data: str) -> Optional[Dict[str, Any]]:
    """解析 hysteria2 协议"""
    try:
        # hysteria2://password@server:port?params#name
        parsed_url = urlparse("hysteria2://" + data)
        
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = unquote(parsed_url.fragment) if parsed_url.fragment else generate_node_name('hysteria2', server, port)
        
        params = parse_qs(parsed_url.query)

        node = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port or 443,
            'password': password,
            'tls': True # Hysteria2 always uses TLS
        }
        
        node['skip-cert-verify'] = (params.get('insecure', ['0'])[0] == '1')
        if 'sni' in params:
            node['sni'] = params['sni'][0]
        if 'alpn' in params:
            node['alpn'] = params['alpn'][0].split(',')
        if 'fastopen' in params:
            node['fast-open'] = (params.get('fastopen', ['0'])[0] == '1')
        
        return node
    except Exception as e:
        print(f"Error parsing hysteria2 data '{data[:50]}...': {e}")
        return None

def parse_ssr(data: str) -> Optional[Dict[str, Any]]:
    """解析 ssr 协议"""
    try:
        # SSR links have custom base64 encoding and parameters
        decoded_data = base64.b64decode(data.replace('-', '+').replace('_', '/') + '==').decode('utf-8') # Custom base64 + padding
        
        parts = decoded_data.split(':')
        if len(parts) < 6:
            print(f"SSR data has too few parts: {decoded_data[:50]}...")
            return None

        server = parts[0]
        port = int(parts[1])
        protocol = parts[2]
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
            'protocol': protocol,
            'protocol-param': protocol_param,
            'obfs': obfs,
            'obfs-param': obfs_param
        }
        return node
    except Exception as e:
        print(f"Error parsing ssr data '{data[:50]}...': {e}")
        return None

def parse_line_as_node(line: str) -> List[Dict[str, Any]]:
    """尝试将单行字符串解析为一个或多个节点"""
    nodes = []
    line = line.strip()
    if not line:
        return nodes

    # 尝试直接解析协议
    for protocol in SUPPORTED_PROTOCOLS:
        if line.startswith(f"{protocol}://"):
            # 对于 ssr://, vmess://, hysteria2://，其数据部分本身可能就是base64编码的
            # 对于 trojan://, vless://，其数据部分通常是明文 (password@server:port...)
            # 对于 ss://，其数据部分是base64编码的 (method:password@server:port)
            
            # 提取协议后的数据部分
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
                node = parser(data_part) # 传递数据部分给解析器
                if node:
                    nodes.append(node)
                else:
                    print(f"Failed to parse {protocol} node from line: {line[:100]}...")
            return nodes # 如果匹配到协议，就尝试解析并返回，不再进行多层Base64

    # 如果不是直接的协议链接，尝试多层 Base64 解码，然后再次尝试解析协议
    decoded_content = line
    for _ in range(5): # 尝试解码最多5次
        try:
            temp_decoded = base64.b64decode(decoded_content + '==').decode('utf-8')
            # 检查是否是新的协议链接，如果是，则停止解码并解析
            for protocol in SUPPORTED_PROTOCOLS:
                if temp_decoded.startswith(f"{protocol}://"):
                    # 如果解码后是协议链接，则递归调用自身来解析这个新链接
                    nodes.extend(parse_line_as_node(temp_decoded))
                    return nodes # 已经解析，直接返回
            decoded_content = temp_decoded # 如果不是协议链接，继续尝试解码
        except Exception:
            break # 解码失败或不再是Base64，停止循环

    # 如果多层Base64解码后依然无法识别为协议链接，可能是Clash格式的字典，或者无法识别的格式
    # 这部分逻辑将由 parse_content 统一处理
    return nodes


def parse_content(content: str) -> List[Dict[str, Any]]:
    """解析内容，可能包含多行节点、YAML 或 JSON"""
    nodes: List[Dict[str, Any]] = []
    
    # 尝试解析 YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # Clash 配置通常在 'proxies' 键下
            if 'proxies' in data and isinstance(data['proxies'], list):
                nodes.extend(data['proxies'])
            else: # 如果整个YAML是一个Clash node的字典，直接加入
                # 这部分需要更精确的判断，防止解析到非节点信息
                # 简单判断一些关键键是否存在
                if all(k in data for k in ['name', 'type', 'server', 'port']):
                     nodes.append(data)
                
        elif isinstance(data, list): # 可能是直接的节点列表
            for item in data:
                if isinstance(item, dict) and all(k in item for k in ['name', 'type', 'server', 'port']):
                    nodes.append(item)
                elif isinstance(item, str): # 列表中可能是字符串形式的节点链接
                    nodes.extend(parse_line_as_node(item))
        print(f"Content parsed as YAML, found {len(nodes)} nodes.")
        if nodes: # 如果成功解析到节点，就返回，不再尝试其他方式
            return nodes
    except yaml.YAMLError as e:
        # print(f"Content is not valid YAML or a proxy list: {e}")
        pass # 不是YAML，继续尝试其他格式

    # 尝试解析 JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            if 'proxies' in data and isinstance(data['proxies'], list):
                nodes.extend(data['proxies'])
            else: # 如果整个JSON是一个Clash node的字典，直接加入
                if all(k in data for k in ['name', 'type', 'server', 'port']):
                     nodes.append(data)
        elif isinstance(data, list): # 可能是直接的节点列表
            for item in data:
                if isinstance(item, dict) and all(k in item for k in ['name', 'type', 'server', 'port']):
                    nodes.append(item)
                elif isinstance(item, str): # 列表中可能是字符串形式的节点链接
                    nodes.extend(parse_line_as_node(item))
        print(f"Content parsed as JSON, found {len(nodes)} nodes.")
        if nodes: # 如果成功解析到节点，就返回
            return nodes
    except json.JSONDecodeError as e:
        # print(f"Content is not valid JSON or a proxy list: {e}")
        pass # 不是JSON，继续尝试其他格式

    # 按行解析（可能是 Base64 编码的多行节点，或直接的协议链接）
    # 如果前面 YAML/JSON 解析成功，就不会执行到这里
    for i, line in enumerate(content.splitlines()):
        line_nodes = parse_line_as_node(line)
        if line_nodes:
            nodes.extend(line_nodes)
        else:
            if line.strip(): # 打印无法解析的非空行
                print(f"Could not parse line {i+1} as a node: {line.strip()[:100]}...")

    return nodes

def get_output_filename(url: str) -> str:
    """根据 URL 路径确定输出文件名"""
    parsed_url = urlparse(url)
    path_segments = [s for s in parsed_url.path.split('/') if s] # Remove empty strings
    
    # 尝试从路径中获取文件名
    if path_segments:
        # 移除文件扩展名，并取最后一段作为基础名
        base_filename = path_segments[-1].split('.')[0] if '.' in path_segments[-1] else path_segments[-1]
        
        # 特殊处理，例如 raw.githubusercontent.com 的路径可能太长
        if "raw.githubusercontent.com" in parsed_url.hostname:
            repo_parts = parsed_url.path.split('/')
            if len(repo_parts) >= 3: # /user/repo/branch/...
                # Take user_repo_basefilename
                filename_parts = [repo_parts[1], repo_parts[2]]
                if base_filename and base_filename not in filename_parts: # Add actual file name if distinct
                    filename_parts.append(base_filename)
                return "_".join(filename_parts).replace('-', '_') + ".yaml"
            elif base_filename:
                return base_filename.replace('-', '_') + ".yaml"
        
        # 否则使用简化路径作为文件名
        # 比如 /path/to/file.txt -> file.yaml
        # /~250630 -> 250630.yaml
        if base_filename:
            return base_filename.replace('~', '').replace('.', '_').replace('-', '_') + ".yaml"

    # 如果路径为空或无法识别，使用域名作为基础文件名
    hostname_clean = parsed_url.hostname.replace('.', '_').replace('-', '_')
    if hostname_clean:
        return f"{hostname_clean}.yaml"
    
    # 最后兜底
    return "default_nodes.yaml"

def save_to_yaml(nodes: List[Dict[str, Any]], output_filepath: str):
    """保存节点到 YAML 文件"""
    if not nodes:
        print(f"No valid nodes extracted for {output_filepath}. Skipping file creation.")
        return
        
    os.makedirs(os.path.dirname(output_filepath), exist_ok=True) # Ensure directory exists
    
    yaml_data = {'proxies': nodes}
    
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            yaml.dump(yaml_data, f, allow_unicode=True, indent=2, sort_keys=False)
        print(f"Successfully saved {len(nodes)} nodes to {output_filepath}")
    except Exception as e:
        print(f"Error saving nodes to {output_filepath}: {e}")

async def process_url(session: aiohttp.ClientSession, url: str):
    """处理单个 URL"""
    content = await fetch_url(session, url)
    if not content:
        print(f"No content fetched from {url}, skipping parsing.")
        return

    nodes = parse_content(content)
    
    output_filename = get_output_filename(url)
    output_filepath = os.path.join('sc', output_filename)
    save_to_yaml(nodes, output_filepath)

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
        # This part is typically for Pyodide/WebAssembly environments
        # On GitHub Actions, asyncio.run() is sufficient.
        asyncio.ensure_future(main())
    else:
        asyncio.run(main())
