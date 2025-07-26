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

# --- 配置常量 ---
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=10000000" # 10MB 测试文件
OUTPUT_DIR = "sc"
PROJECT_NAME = "NodeDownloadSpeedTest"
# 本地代理端口，确保不冲突
XRAY_SOCKS_PORT = 1080
HYSTERIA_SOCKS_PORT = 1081 # 对应Hysteria V1
HYSTERIA2_SOCKS_PORT = 1082 # 对应Hysteria2

# --- 全局代理设置辅助函数 ---
def set_global_socks_proxy(host, port):
    """设置全局 SOCKS5 代理"""
    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket

def reset_global_socks_proxy():
    """重置全局代理设置"""
    socks.set_default_proxy()
    # 恢复默认 socket，否则后续可能报错
    if hasattr(socket, '_socket') and hasattr(socket._socket, 'socket'):
        socket.socket = socket._socket.socket
    else:
        # Fallback for environments where _socket.socket is not directly available
        # This might not perfectly restore, but avoids crashes
        pass

# --- 节点解析函数 ---
def decode_node(node_str):
    """解析节点URL，返回结构化的配置和可能的错误信息"""
    try:
        if node_str.startswith("ss://"):
            user_info_encoded, server_info = node_str[5:].split("@", 1)
            user_info = base64.urlsafe_b64decode(user_info_encoded + "===").decode("utf-8", errors="ignore")
            method, password = user_info.split(":")
            server, port_str = server_info.split(":")
            port = int(port_str.split("#")[0])
            name = unquote(port_str.split("#", 1)[1]) if "#" in port_str else f"{server}:{port}"
            return {"type": "ss", "server": server, "port": port, "method": method, "password": password, "name": name, "original_url": node_str}, None
        elif node_str.startswith("ssr://"):
            decoded = base64.urlsafe_b64decode(node_str[6:] + "===").decode("utf-8", errors="ignore")
            parts = decoded.split(":")
            server, port_str, protocol, method, obfs, password_encoded = parts[:6]
            password = base64.urlsafe_b64decode(password_encoded + "===").decode("utf-8", errors="ignore")
            params = parse_qs(urlparse(decoded).query)
            name = unquote(params.get("remarks", [""])[0]) or f"{server}:{port_str}"
            return {"type": "ssr", "server": server, "port": int(port_str), "protocol": protocol, "method": method, "obfs": obfs, "password": password, "name": name, "original_url": node_str}, None
        elif node_str.startswith("vmess://"):
            decoded = base64.urlsafe_b64decode(node_str[8:] + "===").decode("utf-8", errors="ignore")
            config = json.loads(decoded)
            return {"type": "vmess", "server": config["add"], "port": int(config["port"]), "id": config["id"], "net": config.get("net", "tcp"), "ps": config.get("ps", f"{config['add']}:{config['port']}"), "original_url": node_str}, None
        elif node_str.startswith("trojan://"):
            password, server_info = node_str[9:].split("@", 1)
            server_port_part = server_info.split("?")[0]
            server, port_str = server_port_part.split(":")
            port = int(port_str)
            name = unquote(server_info.split("#", 1)[1]) if "#" in server_info else f"{server}:{port}"
            return {"type": "trojan", "server": server, "port": port, "password": password, "name": name, "original_url": node_str}, None
        elif node_str.startswith("vless://"):
            user_id, server_info = node_str[8:].split("@", 1)
            server_port_part = server_info.split("?")[0]
            server, port_str = server_port_part.split(":")
            port = int(port_str)
            name = unquote(server_info.split("#", 1)[1]) if "#" in server_info else f"{server}:{port}"
            return {"type": "vless", "server": server, "port": port, "id": user_id, "name": name, "original_url": node_str}, None
        elif node_str.startswith("hysteria2://"):
            password, server_info = node_str[12:].split("@", 1)
            server_port_part = server_info.split("?")[0]
            server, port_str = server_port_part.split(":")
            port = int(port_str)
            name = unquote(server_info.split("#", 1)[1]) if "#" in server_info else f"{server}:{port}"
            return {"type": "hysteria2", "server": server, "port": port, "password": password, "name": name, "original_url": node_str}, None
        else:
            # 尝试解析明文 YAML 或 JSON 格式
            try:
                # 尝试 YAML
                config = yaml.safe_load(node_str)
                if isinstance(config, dict) and "port" in config and "server" in config:
                    # 假定这是一个简化的YAML节点配置
                    node_type = config.get("type", "unknown")
                    name = config.get("name", f"{config['server']}:{config['port']}")
                    return {"type": node_type, "server": config["server"], "port": int(config["port"]), "name": name, "original_url": node_str, "raw_config": config}, None
            except yaml.YAMLError:
                pass
            try:
                # 尝试 JSON
                config = json.loads(node_str)
                if isinstance(config, dict) and "add" in config and "port" in config:
                    # 假定这是一个简化的VMess JSON配置
                    return {"type": "vmess", "server": config["add"], "port": int(config["port"]), "id": config.get("id", ""), "net": config.get("net", "tcp"), "ps": config.get("ps", f"{config['add']}:{config['port']}"), "name": config.get("ps", f"{config['add']}:{config['port']}"), "original_url": node_str}, None
            except json.JSONDecodeError:
                pass
            return None, "不支持的节点格式或明文解析失败"
    except Exception as e:
        return None, f"解析节点失败: {e}"

# --- 获取节点列表 ---
def fetch_node_list():
    """从URL获取节点列表"""
    try:
        response = requests.get(NODE_LIST_URL, timeout=10)
        response.raise_for_status() # 检查HTTP错误
        nodes = [line.strip() for line in response.text.splitlines() if line.strip()]
        return nodes
    except requests.exceptions.RequestException as e:
        print(f"获取节点列表失败: {e}")
        return []

# --- 代理配置文件生成 ---
def generate_xray_config(node_config, proxy_port):
    """根据节点配置生成 Xray 配置文件内容"""
    outbound = {
        "protocol": node_config["type"],
        "settings": {},
        "tag": "proxy"
    }

    stream_settings = {"network": node_config.get("net", "tcp")}
    if "ws" in stream_settings["network"]:
        stream_settings["wsSettings"] = {"path": node_config.get("path", "/"), "headers": {"Host": node_config.get("host", node_config['server'])}}
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
        # SSR 在 Xray 中通过 Shadowsocks 协议扩展实现，需要较复杂的配置
        # 为了简化，这里可能不完全支持所有 SSR 特性，只转换基本SS部分
        # 建议SSRR等复杂协议直接通过Xray自身的配置转换工具，或用户自行提供兼容Xray的SS/VMess等
        return None # 暂时不支持在Xray中直接配置SSR
    elif node_config["type"] == "vmess":
        users = [{"id": node_config["id"], "alterId": node_config.get("aid", 0)}] # 假设 aid 为 0
        outbound["settings"]["vnext"] = [{
            "address": node_config["server"],
            "port": node_config["port"],
            "users": users
        }]
        outbound["streamSettings"] = stream_settings
    elif node_config["type"] == "vless":
        users = [{"id": node_config["id"], "flow": node_config.get("flow", "")}] # 假设 flow
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
            "flow": node_config.get("flow", "") # 可选 flow
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
                {"type": "field", "outboundTag": "direct", "port": "0-65535"} # Fallback
            ]
        }
    }
    return json.dumps(xray_config, indent=2)

def generate_hysteria_config(node_config, proxy_port):
    """根据节点配置生成 Hysteria 客户端配置文件内容 (Hysteria V1)"""
    # Hysteria V1 配置文件通常更简单
    hysteria_config = {
        "listen": f"socks5://0.0.0.0:{proxy_port}",
        "server": f"{node_config['server']}:{node_config['port']}",
        "up_mbps": node_config.get("up_mbps", 10), # 默认值
        "down_mbps": node_config.get("down_mbps", 100), # 默认值
        "password": node_config['password'],
        "alpn": node_config.get("alpn", "h3"), # 默认 alpn
        "bandwidth": {
            "up": f"{node_config.get('up_mbps', 10)}Mbps",
            "down": f"{node_config.get('down_mbps', 100)}Mbps"
        },
        "tls": {
            "disable_sni": True,
            "insecure": True # 测试时可以 Insecure，生产不建议
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
            "insecure": node_config.get("tls_insecure", True), # 测试时可以 Insecure，生产不建议
            "sni": node_config.get("tls_sni", node_config['server']),
            "ca": node_config.get("tls_ca", "")
        },
        "obfs": node_config.get("obfs", "none"),
        "obfs_password": node_config.get("obfs_password", "")
    }
    return json.dumps(hysteria2_config, indent=2)

# --- 测速核心逻辑 ---
def test_download_speed(node_info):
    """
    测试单个节点的下载速度。
    根据节点类型启动不同的本地代理客户端。
    """
    node_url, node_config = node_info
    node_type = node_config.get("type")
    node_name = node_config.get("name", node_url) # 使用解析出的名称
    
    local_proxy_process = None
    proxy_port_to_use = None
    proxy_executable_path = None
    config_file_path = None
    proxy_command = []

    print(f"准备测试节点: {node_name} ({node_type})")

    try:
        # Xray 处理大部分协议
        if node_type in ["ss", "vmess", "vless", "trojan"]:
            proxy_port_to_use = XRAY_SOCKS_PORT
            config_file_path = f"/tmp/xray_config_{os.getpid()}.json" # 使用PID确保唯一性
            xray_config_content = generate_xray_config(node_config, proxy_port_to_use)
            
            if not xray_config_content:
                return node_url, 0, f"Xray 配置生成失败或不支持 {node_type} 协议的完整配置"

            with open(config_file_path, "w") as f:
                f.write(xray_config_content)
            
            proxy_executable_path = "./xray"
            proxy_command = [proxy_executable_path, "run", "-c", config_file_path]
            print(f"启动 Xray 代理 ({node_type}) on port {proxy_port_to_use} for {node_name}")
            
        elif node_type == "hysteria2":
            proxy_port_to_use = HYSTERIA2_SOCKS_PORT
            config_file_path = f"/tmp/hysteria2_config_{os.getpid()}.json"
            h2_config_content = generate_hysteria2_config(node_config, proxy_port_to_use)

            if not h2_config_content:
                return node_url, 0, f"Hysteria2 配置生成失败"
            
            with open(config_file_path, "w") as f:
                f.write(h2_config_content)
            
            proxy_executable_path = "./hysteria2"
            proxy_command = [proxy_executable_path, "run", "-c", config_file_path]
            print(f"启动 Hysteria2 代理 ({node_type}) on port {proxy_port_to_use} for {node_name}")
            
        elif node_type == "ssr":
            # SSR 比较特殊，如果 Xray 不支持，可能需要 SSR 专用客户端
            # 目前Xray对SSR支持有限，且可能需要额外的插件/配置。
            # 这里暂时标记为不支持，或者可以考虑通过其他工具转换成SS/VMess再测试
            return node_url, 0, f"暂不支持 SSR 协议的直接下载测速 (复杂性较高)"
            
        else:
            return node_url, 0, f"暂不支持 {node_type} 协议的下载测速"

        # 启动本地代理进程
        local_proxy_process = subprocess.Popen(proxy_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3) # 给予代理客户端足够时间启动

        # 检查代理进程是否成功启动
        poll_result = local_proxy_process.poll()
        if poll_result is not None: # 如果进程已退出
            stdout, stderr = local_proxy_process.communicate()
            return node_url, 0, f"代理客户端 {proxy_executable_path} 启动失败 (Exit Code: {poll_result}). STDOUT: {stdout.decode(errors='ignore')}. STDERR: {stderr.decode(errors='ignore')}"

        # 设置 requests 使用本地代理
        set_global_socks_proxy("127.0.0.1", proxy_port_to_use)
        session = requests.Session()

        start_time = time.time()
        response = session.get(TEST_FILE_URL, stream=True, timeout=15) # 增加超时时间
        response.raise_for_status() # 检查HTTP状态码

        downloaded_bytes = 0
        # 限制下载量 (例如 5MB)，防止长时间运行
        for chunk in response.iter_content(chunk_size=4096):
            if chunk: # 确保接收到数据块
                downloaded_bytes += len(chunk)
            if downloaded_bytes >= 5 * 1024 * 1024:
                break
        end_time = time.time()

        duration = end_time - start_time
        if duration == 0:
            speed_mbps = 0
        else:
            speed_mbps = (downloaded_bytes * 8 / 1024 / 1024) / duration
        
        if downloaded_bytes == 0:
            return node_url, 0, "未下载到任何数据 (代理连接可能失败或测试目标无响应)"

        return node_url, speed_mbps, None

    except requests.exceptions.RequestException as e:
        return node_url, 0, f"网络请求失败或代理连接问题: {e}"
    except Exception as e:
        return node_url, 0, f"测试过程中发生错误: {type(e).__name__}: {e}"
    finally:
        # 清理：停止代理进程
        if local_proxy_process:
            print(f"停止代理进程 for {node_name}")
            local_proxy_process.terminate()
            try:
                local_proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                local_proxy_process.kill() # 如果 terminate 不够，强制杀死
        # 恢复默认 socket 设置
        reset_global_socks_proxy()
        # 清理配置文件
        if config_file_path and os.path.exists(config_file_path):
            os.remove(config_file_path)

# --- 主函数 ---
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    nodes_raw = fetch_node_list()
    if not nodes_raw:
        print("未获取到节点列表，退出程序。")
        return

    nodes_to_test = []
    print(f"从订阅获取到 {len(nodes_raw)} 个原始节点。开始解析...")
    for node_str in nodes_raw:
        config, error = decode_node(node_str)
        if error:
            print(f"警告: 节点 '{node_str[:50]}...' 解析失败: {error}")
            continue
        if config:
            nodes_to_test.append((node_str, config))
    
    if not nodes_to_test:
        print("没有可用于测试的有效节点。请检查节点格式或订阅内容。")
        return

    print(f"成功解析 {len(nodes_to_test)} 个有效节点，开始测试...")

    results = []
    # 限制并发数，避免GitHub Actions资源限制或被目标网站封禁
    # 可以根据节点数量和GitHub Actions的免费额度调整
    max_workers = 3 
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {executor.submit(test_download_speed, node_info): node_info for node_info in nodes_to_test}
        for i, future in enumerate(future_to_node):
            node_url, speed_mbps, error = future.result()
            node_name = next((cfg['name'] for _, cfg in nodes_to_test if _ == node_url), node_url)
            status_msg = f"速度: {speed_mbps:.2f} Mbps" if not error else f"错误: {error}"
            print(f"[{i+1}/{len(nodes_to_test)}] 节点: {node_name[:40]}... -> {status_msg}")
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
        f.write("节点下载速度测试结果\n")
        f.write(f"测试时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
        f.write(f"测试文件: {TEST_FILE_URL}\n")
        f.write("-" * 50 + "\n")
        for res in results:
            f.write(f"节点名称: {res['name']}\n")
            f.write(f"原始URL: {res['node_url']}\n")
            if res["error"]:
                f.write(f"状态: 失败\n错误: {res['error']}\n")
            else:
                f.write(f"状态: 成功\n速度: {res['speed_mbps']:.2f} Mbps\n")
            f.write("-" * 50 + "\n")
    
    # 也可以输出为 YAML 格式，方便机器读取
    with open(output_file_yaml, "w", encoding="utf-8") as f:
        yaml.dump(results, f, allow_unicode=True, default_flow_style=False)

    print(f"测试完成，结果已保存到 {output_file_txt} 和 {output_file_yaml}")

if __name__ == "__main__":
    main()
