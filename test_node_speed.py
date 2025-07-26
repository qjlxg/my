import requests
import time
import os
import base64
import yaml
import json
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor
import socks
import socket
import subprocess
import platform
import re
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 配置常量 ---
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB 测试文件
OUTPUT_DIR = "sc"
PROJECT_NAME = "NodeDownloadSpeedTest"
XRAY_SOCKS_PORT = 1080
HYSTERIA_SOCKS_PORT = 1081  # Hysteria V1（未在解析中使用）
HYSTERIA2_SOCKS_PORT = 1082  # Hysteria2

# --- 全局代理设置辅助函数 ---
def set_global_socks_proxy(host, port):
    """设置全局 SOCKS5 代理"""
    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket

def reset_global_socks_proxy():
    """重置全局代理设置"""
    socks.set_default_proxy()
    if hasattr(socket, '_socket') and hasattr(socket._socket, 'socket'):
        socket.socket = socket._socket.socket
    else:
        pass

# --- 节点解析函数（已优化） ---
def decode_node(node_str):
    """解析节点 URL，返回结构化配置和可能的错误信息"""
    try:
        # 忽略常见的非代理链接
        if node_str.startswith("http://") or node_str.startswith("https://"):
            return None, "不支持的 HTTP/HTTPS 明文代理或非代理链接"

        # 统一 URL 解析，处理片段和查询参数
        parsed_url = urlparse(node_str)
        scheme = parsed_url.scheme.lower()
        path = parsed_url.path.lstrip('/')  # 移除前导斜杠
        fragment = parsed_url.fragment  # '#' 后的部分
        query_params = parse_qs(parsed_url.query)

        # Base64 解码辅助函数（带填充和错误处理）
        def safe_b64decode(s):
            if not s:
                return ""
            try:
                s_padded = s + '=' * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s_padded).decode("utf-8", errors="ignore")
            except Exception as e:
                logger.warning(f"Base64 解码失败: {str(e)}")
                return ""

        # 处理 IPv6 地址
        netloc = parsed_url.netloc
        server = ""
        port = 0
        if netloc.startswith('['):  # IPv6 地址
            match = re.match(r'\[(.*?)\](?::(\d+))?', netloc)
            if not match:
                return None, f"Invalid {scheme.upper()} IPv6 address format"
            server, port_str = match.groups()
            if not port_str:
                return None, f"{scheme.upper()} 节点缺少端口信息"
            try:
                port = int(port_str)
            except ValueError:
                return None, f"{scheme.upper()} 端口 '{port_str}' 无效"
        else:  # IPv4 或域名
            server_and_port = netloc.split("?")[0]
            if ':' not in server_and_port:
                return None, f"{scheme.upper()} 节点缺少端口信息"
            server, port_str = server_and_port.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return None, f"{scheme.upper()} 端口 '{port_str}' 无效"

        if scheme == "ss":
            # ss://method:password@server:port#name 或 ss://base64encoded@server:port?plugin_params#name
            if '@' not in parsed_url.netloc:
                return None, "SS 节点缺少用户信息"
            user_info_raw, _ = parsed_url.netloc.split("@", 1)
            method = ""
            password = ""
            try:
                decoded_user_info = safe_b64decode(user_info_raw)
                if ':' in decoded_user_info:
                    method, password = decoded_user_info.split(":", 1)
                else:
                    password = decoded_user_info
                    method = query_params.get("method", ["aes-256-gcm"])[0]
            except Exception:
                if ':' in user_info_raw:
                    method, password = user_info_raw.split(":", 1)
                else:
                    return None, "SS 用户信息解析失败"
            name = unquote(fragment) if fragment else f"{server}:{port}"
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
            if '/' in decoded_ssr:
                params_part = decoded_ssr.split('/?')[1] if '/?' in decoded_ssr else ""
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
                "type": config.get("type", ""),
                "host": config.get("host", ""),
                "path": config.get("path", ""),
                "tls": config.get("tls", ""),
                "ps": name,
                "original_url": node_str
            }, None

        elif scheme == "trojan":
            # trojan://password@server:port?query_params#name
            if '@' not in parsed_url.netloc:
                return None, "Trojan 节点缺少密码"
            password_raw, _ = parsed_url.netloc.split("@", 1)
            name = unquote(fragment) if fragment else f"{server}:{port}"
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
            if '@' not in parsed_url.netloc:
                return None, "VLESS 节点缺少用户 ID"
            user_id, _ = parsed_url.netloc.split("@", 1)
            name = unquote(fragment) if fragment else f"{server}:{port}"
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
            if '@' not in parsed_url.netloc:
                return None, "Hysteria2 节点缺少密码"
            password_raw, _ = parsed_url.netloc.split("@", 1)
            name = unquote(fragment) if fragment else f"{server}:{port}"
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

# --- 获取节点列表 ---
def fetch_node_list():
    """从 URL 获取节点列表"""
    try:
        response = requests.get(NODE_LIST_URL, timeout=10)
        response.raise_for_status()
        nodes = [line.strip() for line in response.text.splitlines() if line.strip()]
        return nodes
    except requests.exceptions.RequestException as e:
        logger.error(f"获取节点列表失败: {str(e)}")
        return []

# --- 生成代理配置文件 ---
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
            "disable_sni": True,
            "insecure": True
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

# --- 速度测试核心逻辑 ---
def test_download_speed(node_info):
    """测试单个节点的下载速度，根据节点类型启动本地代理客户端"""
    node_url, node_config = node_info
    node_type = node_config.get("type")
    node_name = node_config.get("name", node_url)
    
    local_proxy_process = None
    proxy_port_to_use = None
    proxy_executable_path = None
    config_file_path = None
    proxy_command = []

    logger.info(f"准备测试节点: {node_name} ({node_type})")

    try:
        if node_type in ["ss", "vmess", "vless", "trojan"]:
            proxy_port_to_use = XRAY_SOCKS_PORT
            config_file_path = f"/tmp/xray_config_{os.getpid()}.json"
            xray_config_content = generate_xray_config(node_config, proxy_port_to_use)
            if not xray_config_content:
                return node_url, 0, f"Xray 配置生成失败或 {node_type} 未完全支持"
            with open(config_file_path, "w") as f:
                f.write(xray_config_content)
            proxy_executable_path = "./xray"
            proxy_command = [proxy_executable_path, "run", "-c", config_file_path]
            logger.info(f"启动 Xray 代理 ({node_type})，端口 {proxy_port_to_use}，节点 {node_name}")

        elif node_type == "hysteria2":
            proxy_port_to_use = HYSTERIA2_SOCKS_PORT
            config_file_path = f"/tmp/hysteria2_config_{os.getpid()}.json"
            h2_config_content = generate_hysteria2_config(node_config, proxy_port_to_use)
            if not h2_config_content:
                return node_url, 0, "Hysteria2 配置生成失败"
            with open(config_file_path, "w") as f:
                f.write(h2_config_content)
            proxy_executable_path = "./hysteria2"
            proxy_command = [proxy_executable_path, "run", "-c", config_file_path]
            logger.info(f"启动 Hysteria2 代理 ({node_type})，端口 {proxy_port_to_use}，节点 {node_name}")

        elif node_type == "ssr":
            return node_url, 0, "SSR 协议暂不支持直接速度测试（复杂度较高）"

        else:
            return node_url, 0, f"不支持的协议 '{node_type}'"

        local_proxy_process = subprocess.Popen(proxy_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)  # 等待代理客户端启动

        # 检查代理进程是否成功启动
        poll_result = local_proxy_process.poll()
        if poll_result is not None:
            stdout, stderr = local_proxy_process.communicate()
            return node_url, 0, f"代理客户端 {proxy_executable_path} 启动失败 (退出码: {poll_result})。STDOUT: {stdout.decode(errors='ignore')}. STDERR: {stderr.decode(errors='ignore')}"

        set_global_socks_proxy("127.0.0.1", proxy_port_to_use)
        session = requests.Session()

        start_time = time.time()
        response = session.get(TEST_FILE_URL, stream=True, timeout=15)
        response.raise_for_status()

        downloaded_bytes = 0
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                downloaded_bytes += len(chunk)
            if downloaded_bytes >= 5 * 1024 * 1024:
                break
        end_time = time.time()

        duration = end_time - start_time
        speed_mbps = 0 if duration == 0 else (downloaded_bytes * 8 / 1024 / 1024) / duration
        if downloaded_bytes == 0:
            return node_url, 0, "未下载到数据（代理连接可能失败或测试目标无响应）"

        return node_url, speed_mbps, None

    except requests.exceptions.RequestException as e:
        return node_url, 0, f"网络请求失败或代理连接问题: {str(e)}"
    except Exception as e:
        return node_url, 0, f"测试过程中发生错误: {type(e).__name__}: {str(e)}"
    finally:
        if local_proxy_process:
            logger.info(f"停止代理进程，节点: {node_name}")
            local_proxy_process.terminate()
            try:
                local_proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                local_proxy_process.kill()
        reset_global_socks_proxy()
        if config_file_path and os.path.exists(config_file_path):
            os.remove(config_file_path)

# --- 主函数 ---
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    nodes_raw = fetch_node_list()
    if not nodes_raw:
        logger.error("无法获取节点列表，程序退出。")
        return

    nodes_to_test = []
    logger.info(f"从订阅获取到 {len(nodes_raw)} 个原始节点，开始解析...")
    for node_str in nodes_raw:
        config, error = decode_node(node_str)
        if error:
            display_node_str = node_str if len(node_str) < 70 else node_str[:67] + "..."
            logger.warning(f"节点 '{display_node_str}' 解析失败: {error}")
            continue
        if config:
            nodes_to_test.append((node_str, config))

    if not nodes_to_test:
        logger.error("未找到可测试的有效节点，请检查节点格式或订阅内容。")
        return

    logger.info(f"成功解析 {len(nodes_to_test)} 个有效节点，开始测试...")

    results = []
    max_workers = 3
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {executor.submit(test_download_speed, node_info): node_info for node_info in nodes_to_test}
        for i, future in enumerate(future_to_node):
            node_url, speed_mbps, error = future.result()
            node_name = next((cfg['name'] for _, cfg in nodes_to_test if _ == node_url), node_url)
            status_msg = f"速度: {speed_mbps:.2f} Mbps" if not error else f"错误: {error}"
            logger.info(f"[{i+1}/{len(nodes_to_test)}] 节点: {node_name[:40]}... -> {status_msg}")
            results.append({
                "name": node_name,
                "node_url": node_url,
                "speed_mbps": speed_mbps,
                "error": error
            })

    results.sort(key=lambda x: x["speed_mbps"], reverse=True)

    output_file_txt = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}.txt")
    output_file_yaml = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}.yaml")

    with open(output_file_txt, "w", encoding="utf-8") as f:
        f.write("Node Download Speed Test Results\n")
        f.write(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
        f.write(f"Test File: {TEST_FILE_URL}\n")
        f.write("-" * 50 + "\n")
        for res in results:
            f.write(f"Node Name: {res['name']}\n")
            f.write(f"Original URL: {res['node_url']}\n")
            if res["error"]:
                f.write(f"Status: Failed\nError: {res['error']}\n")
            else:
                f.write(f"Status: Success\nSpeed: {res['speed_mbps']:.2f} Mbps\n")
            f.write("-" * 50 + "\n")

    with open(output_file_yaml, "w", encoding="utf-8") as f:
        yaml.dump(results, f, allow_unicode=True, default_flow_style=False)

    logger.info(f"测试完成，结果已保存至 {output_file_txt} 和 {output_file_yaml}")

if __name__ == "__main__":
    main()
