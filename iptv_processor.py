import os
import requests
from urllib.parse import urlparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed # 导入并发相关模块
from tqdm import tqdm # 用于显示进度条，需要额外安装

# --- 配置 ---
# 输入文件，包含其他M3U/IPTV列表的URL
URLS_FILE = "sc/urls.txt"
# 输出文件，合并所有节目源后的列表
OUTPUT_IPTV_LIST_FILE = "sc/iptv_list.txt"

# 用于存储下载的原始 M3U 内容的临时目录 (可选，用于调试)
TEMP_DOWNLOAD_DIR = "sc/temp_raw_downloads"

# 并发下载的最大线程数
MAX_WORKERS = 20 # 可以根据你的网络带宽和服务器响应能力调整，过大可能适得其反

# --- 辅助函数 ---

def download_content(url, timeout=10):
    """下载指定URL的内容"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status() # 检查HTTP错误
        return url, response.text # 返回URL和内容
    except requests.exceptions.RequestException as e:
        # print(f"警告: 下载 {url} 失败: {e}") # 并发模式下不直接打印，由主线程统一处理
        return url, None # 返回URL和None表示失败

def parse_m3u_content(content):
    """
    解析M3U/M3U8内容，提取频道名称和URL对。
    也尝试解析 "频道名称,URL" 格式的行。
    返回一个列表，每个元素是一个元组 (channel_name, url_line)。
    """
    lines = content.splitlines()
    streams = []
    current_channel_name = ""
    
    for line in lines:
        line = line.strip()
        if not line: # 跳过空行
            continue

        if line.startswith("#EXTINF"):
            # 提取 EXTINF 后的频道名称
            match = re.search(r',(.+)$', line)
            if match:
                current_channel_name = match.group(1).strip()
            else:
                current_channel_name = "未知频道" # Fallback
        elif line.startswith("http"):
            if current_channel_name:
                streams.append((current_channel_name, line))
                current_channel_name = ""  # 重置，避免一个EXTINF对应多个URL
            else:
                # 如果前面没有EXTINF，但有URL，尝试从URL中提取名称
                parsed_url = urlparse(line)
                name_from_url = os.path.splitext(os.path.basename(parsed_url.path))[0] or "未知频道"
                streams.append((name_from_url, line))
        else:
            # 尝试解析 "频道名称,URL" 格式
            parts = line.split(',', 1)
            if len(parts) == 2 and parts[1].strip().startswith("http"):
                channel_name = parts[0].strip()
                url = parts[1].strip()
                streams.append((channel_name, url))
    return streams

def merge_and_deduplicate_streams(all_streams):
    """合并并去重节目流，按 URL 去重，保留第一个遇到的频道名称"""
    seen_urls = set()
    unique_streams = []
    url_to_stream_info = {} # {url: (channel_name, url)}

    for channel_name, url in all_streams:
        if url not in seen_urls:
            seen_urls.add(url)
            url_to_stream_info[url] = (channel_name, url)
    
    for url in url_to_stream_info:
        unique_streams.append(url_to_stream_info[url])
    
    return unique_streams

def main():
    # 确保输出目录存在
    os.makedirs(os.path.dirname(OUTPUT_IPTV_LIST_FILE), exist_ok=True)
    os.makedirs(TEMP_DOWNLOAD_DIR, exist_ok=True) # 用于保存临时下载的文件

    all_extracted_streams = []
    failed_downloads = []

    print(f"正在读取 {URLS_FILE} 中的源列表...")
    try:
        with open(URLS_FILE, "r", encoding="utf-8") as f:
            source_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"错误: 未找到文件 {URLS_FILE}。请确保文件存在并包含节目源URL。")
        return

    if not source_urls:
        print(f"警告: {URLS_FILE} 中没有找到有效的节目源URL。")
        return

    print(f"将从 {len(source_urls)} 个源并发下载并解析节目列表 (最大并发数: {MAX_WORKERS})...")

    # 使用 ThreadPoolExecutor 进行并发下载
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有下载任务
        future_to_url = {executor.submit(download_content, url): url for url in source_urls}
        
        # 使用 tqdm 显示进度条
        for future in tqdm(as_completed(future_to_url), total=len(source_to_url), desc="下载并解析源"):
            url = future_to_url[future]
            try:
                downloaded_url, content = future.result() # 获取下载结果
                if content:
                    extracted_streams = parse_m3u_content(content)
                    all_extracted_streams.extend(extracted_streams)
                else:
                    failed_downloads.append(downloaded_url)
            except Exception as exc:
                failed_downloads.append(url)
                print(f"下载 {url} 时发生异常: {exc}")

    if failed_downloads:
        print(f"\n警告: 有 {len(failed_downloads)} 个源下载失败或解析失败，已跳过。")
        # 可以选择打印失败的URL列表
        # for url in failed_downloads:
        #     print(f"  - {url}")

    print("\n所有源已下载并解析。正在合并和去重...")
    final_unique_streams = merge_and_deduplicate_streams(all_extracted_streams)
    print(f"合并去重后，共得到 {len(final_unique_streams)} 个唯一节目源。")

    print(f"正在保存最终节目源列表到 {OUTPUT_IPTV_LIST_FILE}...")
    with open(OUTPUT_IPTV_LIST_FILE, "w", encoding="utf-8") as f:
        for channel_name, url in final_unique_streams:
            f.write(f"{channel_name},{url}\n")
    print("保存完成。")
    print(f"最终列表位于: {os.path.abspath(OUTPUT_IPTV_LIST_FILE)}")


if __name__ == "__main__":
    main()
