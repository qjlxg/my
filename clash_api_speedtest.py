import yaml
import requests
import time
import argparse
import asyncio
import aiohttp
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
    parser.add_argument("--min-download", type=float, default=0.0,
                        help="过滤掉下载速度低于此值 (MB/s) 的节点。当前版本不支持真实的下载速度测试，此参数仅作占位符。")
    parser.add_argument("--min-upload", type=float, default=0.0,
                        help="过滤掉上传速度低于此值 (MB/s) 的节点。当前版本不支持真实的上传速度测试，此参数仅作占位符。")
    parser.add_argument("--sort", type=str, default="latency",
                        choices=["latency", "download", "upload"],
                        help="排序方式: latency (延迟)。当前版本只支持按延迟排序。")
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

async def test_proxy_latency_async(session, clash_url, secret, proxy_name, timeout_ms):
    """异步测试代理延迟"""
    url = f"{clash_url}/{CLASH_API_VERSION}/proxies/{proxy_name}/delay?timeout={timeout_ms}&url=http://www.google.com/generate_204"
    headers = get_clash_api_headers(secret)
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_ms/1000 + 5)) as response:
            response.raise_for_status()
            data = await response.json()
            if 'delay' in data:
                return proxy_name, data['delay']
    except aiohttp.client_exceptions.ClientError as e:
        print(f"错误: 测速节点 '{proxy_name}' 延迟时发生请求错误: {e}")
    except asyncio.TimeoutError:
        print(f"警告: 测速节点 '{proxy_name}' 延迟时超时。")
    except Exception as e:
        print(f"错误: 测速节点 '{proxy_name}' 延迟时发生未知错误: {e}")
    return proxy_name, -1 # 返回 -1 表示失败

async def run_tests_concurrently(proxies, clash_url, secret, timeout_ms, concurrent_limit):
    """并发运行延迟测试"""
    tested_results = []
    connector = aiohttp.TCPConnector(limit_per_host=concurrent_limit, ssl=False) # 控制并发
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for proxy in proxies:
            proxy_name = proxy.get('name')
            if proxy_name:
                tasks.append(test_proxy_latency_async(session, clash_url, secret, proxy_name, timeout_ms))
        
        for i, task in enumerate(asyncio.as_completed(tasks)):
            proxy_name, latency = await task
            # 在这里将结果与原始代理对象关联
            original_proxy = next((p for p in proxies if p.get('name') == proxy_name), None)
            if original_proxy:
                if latency != -1:
                    print(f"[{i+1}/{len(proxies)}] 节点: {proxy_name}, 延迟: {latency}ms")
                    original_proxy['latency'] = latency
                    # 占位符，因为当前版本不支持真实速度测试
                    original_proxy['download_speed'] = 0.0
                    original_proxy['upload_speed'] = 0.0
                    tested_results.append(original_proxy)
                else:
                    print(f"[{i+1}/{len(proxies)}] 节点: {proxy_name}, 测速失败或超时，跳过。")
            else:
                print(f"警告: 测速结果中包含未找到的代理名称: {proxy_name}")
    return tested_results


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
    
    # 验证 Clash 核心是否已加载所有代理
    try:
        proxies_status_url = f"{clash_url}/{CLASH_API_VERSION}/proxies"
        headers = get_clash_api_headers(clash_secret)
        response = requests.get(proxies_status_url, headers=headers, timeout=10)
        response.raise_for_status()
        current_proxies_info = response.json().get('proxies', {})
        print(f"Clash 核心已加载 {len(current_proxies_info)} 个代理。")
        
        # 验证所有输入节点是否在 Clash 核心中
        initial_proxy_names = {p['name'] for p in proxies if 'name' in p}
        clash_loaded_proxy_names = set(current_proxies_info.keys())

        missing_nodes = list(initial_proxy_names - clash_loaded_proxy_names)
        if missing_nodes:
            print(f"警告: 以下节点未在 Clash 核心中找到，可能无法被测试: {missing_nodes[:5]}...") # 只显示前5个
            # 过滤掉不在 Clash 核心中的节点
            proxies = [p for p in proxies if p.get('name') in clash_loaded_proxy_names]
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
    tested_proxies = asyncio.run(run_tests_concurrently(proxies, clash_url, clash_secret, args.timeout, args.concurrent))
    
    # 过滤
    filtered_proxies = []
    for proxy in tested_proxies:
        if proxy.get('latency', float('inf')) <= args.max_latency:
            # 真实下载/上传速度测试暂不支持，此处过滤将依赖于占位符
            if proxy.get('download_speed', 0) >= args.min_download and \
               proxy.get('upload_speed', 0) >= args.min_upload:
                filtered_proxies.append(proxy)
            else:
                print(f"  - 节点 '{proxy.get('name')}' 未达到最小速度要求，跳过。")
        else:
            print(f"  - 节点 '{proxy.get('name')}' 延迟 {proxy.get('latency')}ms 超过最大延迟 {args.max_latency}ms，跳过。")

    print(f"测速完成。共有 {len(filtered_proxies)} 个节点通过过滤。")

    # 排序
    if args.sort == "latency":
        filtered_proxies.sort(key=lambda x: x.get('latency', float('inf')))
    elif args.sort == "download": # 仅占位符排序，实际数值为0
        filtered_proxies.sort(key=lambda x: x.get('download_speed', 0), reverse=True)
    elif args.sort == "upload": # 仅占位符排序，实际数值为0
        filtered_proxies.sort(key=lambda x: x.get('upload_speed', 0), reverse=True)

    # 重命名节点并准备输出
    output_proxies = []
    for proxy in filtered_proxies:
        new_proxy = proxy.copy() # 复制，避免修改原始数据
        if args.rename:
            latency = new_proxy.get('latency', 'N/A')
            # 只有当测速数据可用时才添加（目前只有延迟）
            speed_info_parts = []
            if latency != 'N/A':
                speed_info_parts.append(f"L{latency}ms")
            
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
