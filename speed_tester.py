import time
import os
import socks
import socket
import subprocess
import requests
import yaml
import logging
from concurrent.futures import ThreadPoolExecutor

# 从 node_parser 模块导入相关函数
from node_parser import decode_node, generate_xray_config, generate_hysteria2_config

# 配置日志输出格式
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 配置常量 ---
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"  # 节点列表 URL
TEST_FILE_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10MB 测试文件 URL
OUTPUT_DIR = "sc"  # 输出目录
PROJECT_NAME = "NodeDownloadSpeedTest"  # 项目名称
XRAY_SOCKS_PORT = 1080  # Xray SOCKS 代理端口
HYSTERIA_SOCKS_PORT = 1081  # Hysteria V1 端口 (未在解析中使用，但保留以便将来扩展)
HYSTERIA2_SOCKS_PORT = 1082 # Hysteria2 SOCKS 代理端口

# --- 全局代理设置辅助函数 ---
def set_global_socks_proxy(host, port):
    """设置全局 SOCKS5 代理"""
    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket
    logger.debug(f"设置 SOCKS5 代理: {host}:{port}")

def reset_global_socks_proxy():
    """重置全局代理设置"""
    socks.set_default_proxy()
    # 尝试恢复原始 socket
    if hasattr(socket, '_socket') and hasattr(socket._socket, 'socket'):
        socket.socket = socket._socket.socket
    else:
        logger.debug("无法直接恢复默认 socket，跳过")
    logger.debug("重置全局代理设置")

# --- 获取节点列表 ---
def fetch_node_list():
    """从指定 URL 获取节点列表"""
    try:
        response = requests.get(NODE_LIST_URL, timeout=10)
        response.raise_for_status()
        nodes = [line.strip() for line in response.text.splitlines() if line.strip()]
        logger.info(f"成功从 {NODE_LIST_URL} 获取到 {len(nodes)} 个原始节点。")
        return nodes
    except requests.exceptions.RequestException as e:
        logger.error(f"获取节点列表失败: {str(e)}")
        return []

# --- 速度测试核心逻辑 ---
def test_download_speed(node_info):
    """测试单个节点的下载速度，根据节点类型启动本地代理客户端

    Args:
        node_info (tuple): (节点 URL, 节点配置字典)

    Returns:
        tuple: (节点 URL, 下载速度 Mbps, 错误信息)
    """
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
                return node_url, 0, f"Xray 配置生成失败或 {node_type} 协议支持不完整。"
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
                return node_url, 0, "Hysteria2 配置生成失败。"
            with open(config_file_path, "w") as f:
                f.write(h2_config_content)
            proxy_executable_path = "./hysteria2"
            proxy_command = [proxy_executable_path, "run", "-c", config_file_path]
            logger.info(f"启动 Hysteria2 代理 ({node_type})，端口 {proxy_port_to_use}，节点 {node_name}")

        elif node_type == "ssr":
            return node_url, 0, "SSR 协议暂不支持直接速度测试（配置复杂，需要独立客户端或 Xray 高级配置）"

        else:
            return node_url, 0, f"不支持的协议 '{node_type}'。"

        # 启动代理进程
        local_proxy_process = subprocess.Popen(proxy_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)  # 等待代理客户端启动，此时间可能需要根据实际情况调整

        # 检查代理进程是否成功启动
        poll_result = local_proxy_process.poll()
        if poll_result is not None:
            stdout, stderr = local_proxy_process.communicate()
            return node_url, 0, f"代理客户端 {proxy_executable_path} 启动失败 (退出码: {poll_result})。STDOUT: {stdout.decode(errors='ignore')}. STDERR: {stderr.decode(errors='ignore')}"

        # 设置全局 SOCKS 代理并进行下载测试
        set_global_socks_proxy("127.0.0.1", proxy_port_to_use)
        session = requests.Session()

        start_time = time.time()
        response = session.get(TEST_FILE_URL, stream=True, timeout=15) # 增加超时时间以应对慢速连接
        response.raise_for_status()

        downloaded_bytes = 0
        # 仅下载前 5MB 数据以节省时间
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                downloaded_bytes += len(chunk)
            if downloaded_bytes >= 5 * 1024 * 1024:
                break
        end_time = time.time()

        duration = end_time - start_time
        # 计算下载速度，确保 duration 不为零
        speed_mbps = 0 if duration == 0 else (downloaded_bytes * 8 / 1024 / 1024) / duration
        
        if downloaded_bytes == 0:
            return node_url, 0, "未下载到数据（代理连接可能失败或测试目标无响应）"

        return node_url, speed_mbps, None

    except requests.exceptions.RequestException as e:
        return node_url, 0, f"网络请求失败或代理连接问题: {str(e)}"
    except Exception as e:
        return node_url, 0, f"测试过程中发生意外错误: {type(e).__name__}: {str(e)}"
    finally:
        # 清理工作：停止代理进程，重置全局代理，删除配置文件
        if local_proxy_process:
            logger.info(f"停止代理进程，节点: {node_name}")
            local_proxy_process.terminate()
            try:
                local_proxy_process.wait(timeout=5) # 等待进程终止
            except subprocess.TimeoutExpired:
                local_proxy_process.kill() # 强制终止
        reset_global_socks_proxy()
        if config_file_path and os.path.exists(config_file_path):
            os.remove(config_file_path)

# --- 主函数 ---
def main():
    """主函数，执行节点获取、解析和速度测试"""
    os.makedirs(OUTPUT_DIR, exist_ok=True) # 确保输出目录存在
    
    nodes_raw = fetch_node_list()
    if not nodes_raw:
        logger.error("无法获取节点列表，程序退出。")
        return

    nodes_to_test = []
    logger.info(f"开始解析 {len(nodes_raw)} 个原始节点...")
    for node_str in nodes_raw:
        config, error = decode_node(node_str)
        if error:
            # 缩短日志中显示的节点URL，避免过长
            display_node_str = node_str if len(node_str) < 70 else node_str[:67] + "..."
            logger.warning(f"节点 '{display_node_str}' 解析失败: {error}")
            continue
        if config:
            nodes_to_test.append((node_str, config))

    if not nodes_to_test:
        logger.error("未找到可测试的有效节点，请检查节点格式或订阅内容。")
        return

    logger.info(f"成功解析 {len(nodes_to_test)} 个有效节点，开始并行测试...")

    results = []
    max_workers = 5  # 限制并发线程数，防止资源过载，可根据机器性能调整
    # 使用 ThreadPoolExecutor 进行并发测试
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有节点测试任务
        future_to_node = {executor.submit(test_download_speed, node_info): node_info for node_info in nodes_to_test}
        
        # 收集结果并显示进度
        for i, future in enumerate(future_to_node):
            node_url, speed_mbps, error = future.result() # 获取测试结果
            # 根据 node_url 找到原始的节点名称
            node_name = next((cfg['name'] for _, cfg in nodes_to_test if _ == node_url), node_url)
            
            status_msg = f"速度: {speed_mbps:.2f} Mbps" if not error else f"错误: {error}"
            logger.info(f"[{i+1}/{len(nodes_to_test)}] 节点: {node_name[:40]}... -> {status_msg}")
            
            results.append({
                "name": node_name,
                "node_url": node_url,
                "speed_mbps": speed_mbps,
                "error": error
            })

    # 按速度从高到低排序
    results.sort(key=lambda x: x["speed_mbps"], reverse=True)

    # 保存结果到文件
    output_file_txt = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_results.txt")
    output_file_yaml = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_results.yaml")

    with open(output_file_txt, "w", encoding="utf-8") as f:
        f.write("节点下载速度测试结果\n")
        f.write(f"测试时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
        f.write(f"测试文件: {TEST_FILE_URL}\n")
        f.write("-" * 50 + "\n")
        for res in results:
            f.write(f"节点名称: {res['name']}\n")
            f.write(f"原始 URL: {res['node_url']}\n")
            if res["error"]:
                f.write(f"状态: 失败\n错误: {res['error']}\n")
            else:
                f.write(f"状态: 成功\n速度: {res['speed_mbps']:.2f} Mbps\n")
            f.write("-" * 50 + "\n")

    with open(output_file_yaml, "w", encoding="utf-8") as f:
        yaml.dump(results, f, allow_unicode=True, default_flow_style=False)

    logger.info(f"测试完成，结果已保存至 {output_file_txt} 和 {output_file_yaml}")

if __name__ == "__main__":
    main()
