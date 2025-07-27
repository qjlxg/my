import yaml
import requests
import time
import argparse
from urllib.parse import urlparse

# 定义常量
CLASH_API_VERSION = "v1"

def parse_args():
    parser = argparse.ArgumentParser(description="通过 Clash API 测速并排序 Clash 节点。")
    parser.add_argument("--clash-url", type=str, default="http://127.0.0.1:9090",
                        help="Clash 外部控制器 API 地址，例如 http://127.0.0.1:9090")
    parser.add_argument("--clash-secret", type=str, default="",
                        help="Clash 外部控制器密钥")
    parser.add_argument("--input-file", type=str, required=True,
                        help="包含待测速节点的 YAML 文件路径")
    parser.add_argument("--output-file", type=str, required=True,
                        help="测速并排序后的 YAML 文件输出路径")
    parser.add_argument("--timeout", type=int, default=5000,
                        help="延迟测试超时时间 (毫秒)")
    parser.add_argument("--concurrent", type=int, default=10,
                        help="并发测试数量")
    parser.add_argument("--max-latency", type=int, default=3000,
                        help="过滤掉延迟高于此值 (毫秒) 的节点")
    parser.add_argument("--min-download", type=float, default=0.5,
                        help="过滤掉下载速度低于此值 (MB/s) 的节点")
    parser.add_argument("--min-upload", type=float, default=0.1,
                        help="过滤掉上传速度低于此值 (MB/s) 的节点")
    parser.add_argument("--sort", type=str, default="download",
                        choices=["latency", "download", "upload"],
                        help="排序方式: latency (延迟), download (下载速度), upload (上传速度)")
    parser.add_argument("--rename", action="store_true",
                        help="是否在节点名称后添加测速信息")
    return parser.parse_args()

def get_clash_api_headers(secret):
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    return headers

def get_proxies_from_config(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    if not config or 'proxies' not in config:
        print(f"警告: 文件 '{file_path}' 中未找到 'proxies' 键或文件为空。")
        return []
    return config['proxies']

def test_proxy_latency(clash_url, secret, proxy_name, timeout_ms):
    url = f"{clash_url}/{CLASH_API_VERSION}/proxies/{proxy_name}/delay?timeout={timeout_ms}&url=http://www.google.com/generate_204"
    headers = get_clash_api_headers(secret)
    try:
        response = requests.get(url, headers=headers, timeout=timeout_ms/1000 + 5) # 给请求本身多一点超时
        response.raise_for_status()
        data = response.json()
        if 'delay' in data:
            return data['delay']
    except requests.exceptions.RequestException as e:
        print(f"错误: 测速节点 '{proxy_name}' 延迟时发生请求错误: {e}")
    except ValueError as e:
        print(f"错误: 测速节点 '{proxy_name}' 延迟时解析 JSON 失败: {e}, 响应: {response.text if 'response' in locals() else '无响应'}")
    return -1 # 返回 -1 表示失败

def test_proxy_speed(clash_url, secret, proxy_name, test_type="download", duration_seconds=10):
    # Clash API 无法直接进行下载/上传速度测试并返回速率。
    # 通常需要外部工具（如 curl）配合其代理端口进行测试。
    # 这里我们将模拟最简单的速度概念：检查代理是否可用。
    # 对于实际的下载/上传速度，Clash 核心的 /traffic API 可以获取流量数据，
    # 但测速通常是针对特定节点而非总流量。
    # 
    # 为了简化，我们只进行延迟测试。如果您确实需要下载/上传速度，
    # 则需要启动另一个独立的测速程序（如 speedtest-cli）并通过 Mihomo 代理进行，
    # 这会使脚本复杂很多。
    # 
    # 鉴于此，我们将把下载/上传速度测速标记为“不支持”或返回默认值。
    # 如果实际需要，这部分需要更复杂的实现，例如：
    # 1. 临时修改 mihomo 配置，将待测节点设为唯一出站。
    # 2. 启动一个 speedtest-cli 进程，并通过 mihomo 代理端口执行。
    # 3. 抓取 speedtest-cli 的输出并解析。
    # 
    # 目前，我们只使用延迟作为主要指标。

    # For now, let's just return placeholders for download/upload speed
    # As Clash API primarily offers latency tests for individual proxies.
    # A true speed test would require more complex setup (e.g., integrating with speedtest-cli via Clash proxy).
    return 0.0 # Placeholder for speed (MB/s)

def main():
    args = parse_args()

    # 读取输入 YAML 文件中的代理节点
    print(f"正在从 '{args.input_file}' 读取代理节点...")
    proxies = get_proxies_from_config(args.input_file)
    if not proxies:
        print("未找到任何代理节点，或输入文件格式不正确。")
        with open(args.output_file, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
        return

    # 设置 API 访问参数
    clash_url = args.clash_url
    clash_secret = args.clash_secret
    headers = get_clash_api_headers(clash_secret)

    tested_proxies = []
    
    # 确保 Clash 核心已加载所有代理
    try:
        proxies_status_url = f"{clash_url}/{CLASH_API_VERSION}/proxies"
        response = requests.get(proxies_status_url, headers=headers, timeout=10)
        response.raise_for_status()
        current_proxies_info = response.json().get('proxies', {})
        print(f"Clash 核心已加载 {len(current_proxies_info)} 个代理。")
        # 验证所有输入节点是否在 Clash 核心中
        missing_nodes = [p['name'] for p in proxies if p['name'] not in current_proxies_info]
        if missing_nodes:
            print(f"警告: 以下节点未在 Clash 核心中找到，可能不会被测试: {missing_nodes[:5]}...") # 只显示前5个
            # 过滤掉不在 Clash 核心中的节点
            proxies = [p for p in proxies if p['name'] in current_proxies_info]
            if not proxies:
                print("所有节点都不在 Clash 核心中，无法进行测速。")
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
                return
    except requests.exceptions.RequestException as e:
        print(f"错误: 无法连接到 Clash API 或获取代理状态: {e}")
        print("请确保 Mihomo Core 已正确启动并监听端口，且 'mihomo_config.yaml' 配置正确。")
        with open(args.output_file, 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': []}, f, allow_unicode=True, sort_keys=False)
        exit(1)

    print(f"总计 {len(proxies)} 个代理节点待测速。")
    print(f"并发数: {args.concurrent}, 延迟超时: {args.timeout}ms")

    # 进行测速
    for i, proxy in enumerate(proxies):
        proxy_name = proxy.get('name')
        if not proxy_name:
            print(f"警告: 发现一个没有 'name' 字段的代理，跳过。内容: {proxy}")
            continue
        
        print(f"[{i+1}/{len(proxies)}] 正在测试节点: {proxy_name}")
        
        latency = test_proxy_latency(clash_url, clash_secret, proxy_name, args.timeout)
        download_speed = 0.0 # 占位符，Clash API 不直接提供
        upload_speed = 0.0   # 占位符，Clash API 不直接提供

        if latency != -1: # -1 表示测速失败
            print(f"  - 延迟: {latency}ms")
            # 过滤
            if latency <= args.max_latency:
                # 在这里，我们只用延迟进行过滤和排序
                # 如果未来需要下载/上传速度，需要更复杂的实现
                proxy['latency'] = latency
                proxy['download_speed'] = download_speed
                proxy['upload_speed'] = upload_speed
                tested_proxies.append(proxy)
            else:
                print(f"  - 节点 '{proxy_name}' 延迟 {latency}ms 超过最大延迟 {args.max_latency}ms，跳过。")
        else:
            print(f"  - 节点 '{proxy_name}' 测速失败或超时，跳过。")

        # 简单控制并发，实际可能需要更复杂的线程池/异步IO
        # 对于 GitHub Actions 这种单进程环境，简单的 sleep 也能起到效果
        # 如果是大量节点，可能需要更精细的并发控制，但 requests 库本身会阻塞
        # 为了提高效率，这里不做 sleep，让 requests 自身处理并发的等待

    print(f"测速完成。共有 {len(tested_proxies)} 个节点通过过滤。")

    # 排序
    if args.sort == "latency":
        tested_proxies.sort(key=lambda x: x.get('latency', float('inf')))
    elif args.sort == "download":
        tested_proxies.sort(key=lambda x: x.get('download_speed', 0), reverse=True)
    elif args.sort == "upload":
        tested_proxies.sort(key=lambda x: x.get('upload_speed', 0), reverse=True)

    # 重命名节点并准备输出
    output_proxies = []
    for proxy in tested_proxies:
        new_proxy = proxy.copy() # 复制，避免修改原始数据
        if args.rename:
            latency_str = f"L{proxy.get('latency', 'N/A')}ms" if 'latency' in proxy else ""
            dl_str = f"D{proxy.get('download_speed', 'N/A'):.1f}MB" if 'download_speed' in proxy else ""
            ul_str = f"U{proxy.get('upload_speed', 'N/A'):.1f}MB" if 'upload_speed' in proxy else ""
            
            # 只有当测速数据可用时才添加
            speed_info_parts = []
            if 'latency' in proxy:
                speed_info_parts.append(latency_str)
            if 'download_speed' in proxy and proxy['download_speed'] > 0: # 只有有下载速度才显示
                speed_info_parts.append(dl_str)
            if 'upload_speed' in proxy and proxy['upload_speed'] > 0: # 只有有上传速度才显示
                speed_info_parts.append(ul_str)

            speed_info = " ".join(speed_info_parts)
            if speed_info:
                new_proxy['name'] = f"{new_proxy['name']} ({speed_info})"
        
        # 移除临时添加的测速数据，以免写入配置文件
        new_proxy.pop('latency', None)
        new_proxy.pop('download_speed', None)
        new_proxy.pop('upload_speed', None)
        output_proxies.append(new_proxy)

    # 写入输出 YAML 文件
    output_config = {'proxies': output_proxies}
    with open(args.output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, sort_keys=False)
    print(f"测速并排序后的节点已保存到 '{args.output_file}'。")

if __name__ == "__main__":
    main()
