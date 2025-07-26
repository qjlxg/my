import base64
import json
import re
import logging
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)

def safe_b64decode(s):
    """安全的 Base64 解码，处理空字符串和填充问题"""
    if not s:
        return ""
    try:
        s_padded = s + '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s_padded).decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Base64 解码失败: {str(e)}")
        return ""

def decode_node(node_str):
    """解析节点 URL，返回结构化配置和错误信息

    Args:
        node_str (str): 节点 URL 字符串

    Returns:
        tuple: (节点配置字典, 错误信息字符串)，成功时错误信息为 None
    """
    try:
        # 解析 URL
        parsed_url = urlparse(node_str)
        scheme = parsed_url.scheme.lower()
        path = parsed_url.path.lstrip('/')
        fragment = parsed_url.fragment
        query_params = parse_qs(parsed_url.query)

        # 提取服务器和端口，支持 IPv6
        netloc = parsed_url.netloc
        server = ""
        port = 0
        if netloc.startswith('['):  # 处理 IPv6 地址
            match = re.match(r'\[(.*?)\](?::(\d+))?', netloc)
            if not match:
                return None, f"{scheme.upper()} 无效的 IPv6 地址格式"
            server, port_str = match.groups()
            if not port_str:
                return None, f"{scheme.upper()} 节点缺少端口信息"
            try:
                port = int(port_str)
            except ValueError:
                return None, f"{scheme.upper()} 端口 '{port_str}' 无效"
        else:  # 处理 IPv4 或域名
            server_and_port = netloc.split("?")[0]
            if ':' not in server_and_port:
                return None, f"{scheme.upper()} 节点缺少端口信息"
            server, port_str = server_and_port.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return None, f"{scheme.upper()} 端口 '{port_str}' 无效"

        # 解析不同协议
        if scheme == "ss":
            # ss://method:password@server:port#name 或 ss://base64encoded@server:port
            if '@' not in netloc:
                return None, "SS 节点缺少用户信息"
            user_info_raw, _ = netloc.split("@", 1)
            method = ""
            password = ""
            try:
                decoded_user_info = safe_b64decode(user_info_raw)
                if ':' in decoded_user_info:
                    method, password = decoded_user_info.split(":", 1)
                else:
                    password = decoded_user_info
                    method = query_params.get("method", ["aes-256-gcm"])[0] # 默认方法
            except Exception: # Fallback for non-base64 encoded user info
                if ':' in user_info_raw:
                    method, password = user_info_raw.split(":", 1)
                else:
                    return None, "SS 用户信息解析失败"
            name = unquote(fragment) or f"{server}:{port}"
            return {
                "type": "ss",
                "server": server,
                "port": port,
                "method": method,
                "password": password,
                "name": name,
                "original_url": node_str
            }, None

        elif scheme == "ssr":
            # ssr://base64encoded
            if not path:
                return None, "SSR 节点 Base64 部分为空"
            decoded_ssr = safe_b64decode(path)
            parts = decoded_ssr.split(":")
            if len(parts) < 6:
                return None, f"SSR 节点信息不完整 (需要至少6个字段), 实际: {len(parts)}"
            server, port_str, protocol, method, obfs, password_encoded = parts[:6]
            try:
                port = int(port_str)
            except ValueError:
                return None, f"SSR 端口 '{port_str}' 无效"
            password = safe_b64decode(password_encoded)
            obfsparam = protparam = remarks = ""
            if '/?' in decoded_ssr:
                params_part = decoded_ssr.split('/?')[1]
                params = parse_qs(params_part)
                obfsparam = safe_b64decode(params.get('obfsparam', [''])[0])
                protparam = safe_b64decode(params.get('protoparam', [''])[0])
                remarks = safe_b64decode(params.get('remarks', [''])[0])
            name = remarks or unquote(fragment) or f"{server}:{port}"
            return {
                "type": "ssr",
                "server": server,
                "port": port,
                "protocol": protocol,
                "method": method,
                "obfs": obfs,
                "password": password,
                "obfsparam": obfsparam,
                "protparam": protparam,
                "name": name,
                "original_url": node_str
            }, None

        elif scheme == "vmess":
            # vmess://base64encoded_json
            if not path:
                return None, "VMess 节点 Base64 部分为空"
            decoded_vmess = safe_b64decode(path)
            try:
                config = json.loads(decoded_vmess)
            except json.JSONDecodeError:
                return None, "VMess JSON 配置解析失败"
            required_keys = ["add", "port", "id"]
            if not all(k in config for k in required_keys):
                return None, f"VMess 节点缺少必要字段: {required_keys}"
            try:
                port = int(config["port"])
            except ValueError:
                return None, f"VMess 端口 '{config['port']}' 无效"
            name = config.get("ps", f"{config['add']}:{port}")
            return {
                "type": "vmess",
                "server": config["add"],
                "port": port,
                "id": config["id"],
                "aid": int(config.get("aid", 0)),
                "net": config.get("net", "tcp"),
                "type": config.get("type", ""), # This 'type' key seems redundant, consider renaming or removing if not used for protocol type itself
                "host": config.get("host", ""),
                "path": config.get("path", ""),
                "tls": config.get("tls", ""),
                "ps": name,
                "original_url": node_str
            }, None

        elif scheme == "trojan":
            # trojan://password@server:port?query_params#name
            if '@' not in netloc:
                return None, "Trojan 节点缺少密码"
            password_raw, _ = netloc.split("@", 1)
            name = unquote(fragment) or f"{server}:{port}"
            return {
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password_raw,
                "name": name,
                "original_url": node_str
            }, None

        elif scheme == "vless":
            # vless://uuid@server:port?query_params#name
            if '@' not in netloc:
                return None, "VLESS 节点缺少用户 ID"
            user_id, _ = netloc.split("@", 1)
            name = unquote(fragment) or f"{server}:{port}"
            return {
                "type": "vless",
                "server": server,
                "port": port,
                "id": user_id,
                "name": name,
                "original_url": node_str
            }, None

        elif scheme == "hysteria2":
            # hysteria2://password@server:port?query_params#name
            if '@' not in netloc:
                return None, "Hysteria2 节点缺少密码"
            password_raw, _ = netloc.split("@", 1)
            name = unquote(fragment) or f"{server}:{port}"
            return {
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": password_raw,
                "name": name,
                "original_url": node_str
            }, None

        else:
            return None, f"不支持的协议类型: '{scheme}'"

    except Exception as e:
        return None, f"解析节点失败: {type(e).__name__}: {str(e)}"

def generate_xray_config(node_config, proxy_port):
    """根据节点配置生成 Xray 配置文件内容"""
    outbound = {
        "protocol": node_config["type"],
        "settings": {},
        "tag": "proxy"
    }
    stream_settings = {"network": node_config.get("net", "tcp")}
    if "ws" in stream_settings["network"]:
        stream_settings["wsSettings"] = {
            "path": node_config.get("path", "/"),
            "headers": {"Host": node_config.get("host", node_config['server'])}
        }
    elif "grpc" in stream_settings["network"]:
        stream_settings["grpcSettings"] = {"serviceName": node_config.get("serviceName", "")}

    if node_config["type"] == "ss":
        outbound["settings"]["servers"] = [{
            "address": node_config["server"],
            "port": node_config["port"],
            "method": node_config["method"],
            "password": node_config["password"]
        }]
    elif node_config["type"] == "ssr":
        logger.warning("SSR 协议暂不支持直接生成 Xray 配置。")
        return None  # 暂不支持直接 Xray 配置
    elif node_config["type"] == "vmess":
        users = [{"id": node_config["id"], "alterId": node_config.get("aid", 0)}]
        outbound["settings"]["vnext"] = [{
            "address": node_config["server"],
            "port": node_config["port"],
            "users": users
        }]
        outbound["streamSettings"] = stream_settings
    elif node_config["type"] == "vless":
        users = [{"id": node_config["id"], "flow": node_config.get("flow", "")}]
        outbound["settings"]["vnext"] = [{
            "address": node_config["server"],
            "port": node_config["port"],
            "users": users
        }]
        outbound["streamSettings"] = stream_settings
    elif node_config["type"] == "trojan":
        outbound["settings"]["servers"] = [{
            "address": node_config["server"],
            "port": node_config["port"],
            "password": node_config["password"],
            "flow": node_config.get("flow", "")
        }]
        outbound["streamSettings"] = stream_settings
    else:
        logger.warning(f"未知或不支持的 Xray 协议类型: {node_config['type']}")
        return None

    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": proxy_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [
                {"type": "field", "outboundTag": "proxy", "port": str(proxy_port)},
                {"type": "field", "outboundTag": "direct", "port": "0-65535"}
            ]
        }
    }
    return json.dumps(xray_config, indent=2)

def generate_hysteria_config(node_config, proxy_port):
    """根据节点配置生成 Hysteria 客户端配置文件内容 (Hysteria V1)"""
    # 注意：原始代码中的 Hysteria V1 配置可能不完全符合最新 Hysteria 版本要求
    # 此处仅做迁移，实际使用时请参考 Hysteria 官方文档
    hysteria_config = {
        "listen": f"socks5://0.0.0.0:{proxy_port}",
        "server": f"{node_config['server']}:{node_config['port']}",
        "up_mbps": node_config.get("up_mbps", 10),
        "down_mbps": node_config.get("down_mbps", 100),
        "password": node_config['password'],
        "alpn": node_config.get("alpn", "h3"),
        "bandwidth": {
            "up": f"{node_config.get('up_mbps', 10)}Mbps",
            "down": f"{node_config.get('down_mbps', 100)}Mbps"
        },
        "tls": {
            "disable_sni": True, # 这是原始代码中的默认值，实际可能需要根据节点配置
            "insecure": True     # 这是原始代码中的默认值，实际可能需要根据节点配置
        }
    }
    return json.dumps(hysteria_config, indent=2)

def generate_hysteria2_config(node_config, proxy_port):
    """根据节点配置生成 Hysteria2 客户端配置文件内容"""
    hysteria2_config = {
        "listen": f"socks5://0.0.0.0:{proxy_port}",
        "server": f"{node_config['server']}:{node_config['port']}",
        "password": node_config['password'],
        "tls": {
            "disable_sni": node_config.get("tls_disable_sni", False),
            "insecure": node_config.get("tls_insecure", True),
            "sni": node_config.get("tls_sni", node_config['server']),
            "ca": node_config.get("tls_ca", "")
        },
        "obfs": node_config.get("obfs", "none"),
        "obfs_password": node_config.get("obfs_password", "")
    }
    return json.dumps(hysteria2_config, indent=2)
