import os
import requests
from urllib.parse import urlparse
import re
from datetime import datetime, timedelta
import pytz # 用于处理时区，确保定时任务时间准确

# --- 配置 ---
# GitHub 仓库信息 (替换为你的仓库信息)
GITHUB_REPO_OWNER = "你的GitHub用户名" # 例如: "你的GitHub用户名"
GITHUB_REPO_NAME = "你的仓库名称"   # 例如: "IPTV_Auto_Update"
GITHUB_BRANCH = "main"             # 你的主分支名称，通常是 'main' 或 'master'

# 输出文件路径
OUTPUT_DIR = "output"
FINAL_M3U_FILE = os.path.join(OUTPUT_DIR, "merged_live.m3u")
TESTED_M3U_FILE = os.path.join(OUTPUT_DIR, "tested_live.m3u")
LAST_UPDATE_FILE = os.path.join(OUTPUT_DIR, "last_update.txt") # 记录上次更新时间的文件

# IPTV 节目源列表 (从 GitHub 原始链接下载的 M3U/M3U8 文件)
github_m3u_urls = [
    "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/cn.m3u", # 示例：中国频道
    "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/us.m3u", # 示例：美国频道
    # 加入新的来源
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/iptv_list.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/list.txt"
    # 暂时移除 fanmingming/live，因为它目前显示 404，您可以自行查找并替换为有效的链接
    # "https://raw.githubusercontent.com/fanmingming/live/main/live.m3u"
    # 更多示例：
    # "https://raw.githubusercontent.com/Blackeaglez/IPTV/main/All.m3u",
    # "https://raw.githubusercontent.com/free-iptv/free-iptv-live/master/channels.m3u"
    # 建议您定期检查这些URL是否仍然有效，因为免费源可能经常变动。
]

# 用于存储下载的原始 M3U 内容的目录
RAW_M3U_DIR = os.path.join(OUTPUT_DIR, "raw_m3u")

# 错误日志文件
ERROR_LOG_FILE = "error_log.txt"

# --- 辅助函数 ---

def log_error(message):
    """记录错误信息到日志文件"""
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(f"错误: {message}")

def download_m3u(url, save_path):
    """下载 M3U/M3U8 文件"""
    print(f"正在下载: {url}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # 检查HTTP错误
        content = response.text
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"下载成功并保存到: {save_path}")
        return content
    except requests.exceptions.RequestException as e:
        log_error(f"下载失败 {url}: {e}")
        return None

def parse_m3u_content(content):
    """
    解析M3U/M3U8内容，提取EXTINF和URL对。
    也尝试解析 "频道名称,URL" 格式的行。
    返回一个列表，每个元素是一个元组 (extinf_line, url_line)。
    """
    lines = content.splitlines()
    streams = []
    current_extinf = ""
    for line in lines:
        line = line.strip()
        if not line: # 跳过空行
            continue

        if line.startswith("#EXTINF"):
            current_extinf = line
        elif line.startswith("http"):
            if current_extinf:
                streams.append((current_extinf, line))
                current_extinf = ""  # 重置，避免一个EXTINF对应多个URL
            else:
                # 如果前面没有EXTINF，但有URL，将其作为单独的流处理
                streams.append(("", line))
        else:
            # 尝试解析 "频道名称,URL" 格式
            # 注意: 这种格式的行不应以 #EXTINF 或 http 开头
            parts = line.split(',', 1) # 只分割一次，避免频道名称中包含逗号的问题
            if len(parts) == 2 and parts[1].strip().startswith("http"):
                channel_name = parts[0].strip()
                url = parts[1].strip()
                # 将其转换为标准的 #EXTINF 格式，以便后续处理
                # -1 表示未知时长，您可以添加更多属性如 group-title="自定义"
                synthetic_extinf = f"#EXTINF:-1,{channel_name}"
                streams.append((synthetic_extinf, url))
                current_extinf = "" # 重置，避免影响下一行
            # else:
                # 如果需要调试，可以取消下面这行的注释，查看无法识别的行
                # print(f"DEBUG: 无法识别的行格式: {line[:100]}...")
    return streams

def merge_and_deduplicate_streams(all_streams):
    """合并并去重节目流，优先保留原始 EXTINF 信息，按 URL 去重"""
    seen_urls = set()
    unique_streams = []
    
    # 使用字典来存储每个 URL 对应的 EXTINF 行，以便保留第一个遇到的 EXTINF 信息
    url_to_extinf = {}

    for extinf, url in all_streams:
        if url not in seen_urls:
            seen_urls.add(url)
            # 如果是空EXTINF，尝试从URL中提取频道名作为EXTINF的title
            if not extinf:
                # 尝试从URL路径中提取名称，或者使用一个通用名称
                parsed_url = urlparse(url)
                path_segments = [s for s in parsed_url.path.split('/') if s]
                if path_segments:
                    # 取最后一个路径段作为名称，去除文件扩展名
                    name_from_url = os.path.splitext(path_segments[-1])[0]
                    extinf = f"#EXTINF:-1,{name_from_url}"
                else:
                    extinf = "#EXTINF:-1,未知频道"
            
            # 存储或更新URL对应的EXTINF
            # 这里是去重逻辑的核心：如果URL重复，我们只保留第一次遇到的EXTINF
            # 如果你想保留最后遇到的，可以调换顺序
            if url not in url_to_extinf:
                url_to_extinf[url] = extinf
            
            # unique_streams.append((extinf, url)) # 如果不去重，直接添加

    # 从字典中生成最终的唯一节目流列表
    for url, extinf in url_to_extinf.items():
        unique_streams.append((extinf, url))

    return unique_streams

def check_stream_status(url, timeout=5):
    """检查 IPTV 流是否可达 (不下载完整流)"""
    try:
        # 只发送 HEAD 请求，获取响应头，不下载内容
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        # 检查状态码，2xx 表示成功，3xx 表示重定向 (allow_redirects=True 会跟随)
        if 200 <= response.status_code < 400:
            return True
        else:
            print(f"URL {url} 返回状态码 {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        # print(f"URL {url} 无法访问: {e}")
        return False

def generate_m3u_file(streams, output_file_path, header_comment=""):
    """生成 M3U 文件"""
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        if header_comment:
            f.write(f"# {header_comment}\n")
        for extinf, url in streams:
            f.write(f"{extinf}\n")
            f.write(f"{url}\n")
    print(f"M3U 文件已生成: {output_file_path}")

def update_last_update_time():
    """更新上次更新时间文件"""
    jst = pytz.timezone('Asia/Tokyo')
    now = datetime.now(jst)
    with open(LAST_UPDATE_FILE, "w", encoding="utf-8") as f:
        # 写入 UTC 时间和 JST 时间
        f.write(f"Last updated (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"Last updated (JST): {now.strftime('%Y-%m-%d %H:%M:%S JST')}\n")
    print(f"更新时间已记录到 {LAST_UPDATE_FILE}")

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RAW_M3U_DIR, exist_ok=True)
    
    all_downloaded_streams = []

    # --- 步骤 1: 获取/下载原始IPTV节目源 ---
    print("\n--- 步骤 1: 获取/下载原始IPTV节目源 ---")
    for i, url in enumerate(github_m3u_urls):
        file_name = f"raw_source_{i+1}_{urlparse(url).netloc.replace('.', '_')}.m3u"
        save_path = os.path.join(RAW_M3U_DIR, file_name)
        content = download_m3u(url, save_path)
        if content:
            all_downloaded_streams.extend(parse_m3u_content(content))

    # --- 步骤 2: 合并和去重 ---
    print("\n--- 步骤 2: 合并和去重节目源 ---")
    merged_unique_streams = merge_and_deduplicate_streams(all_downloaded_streams)
    print(f"合并去重后，共得到 {len(merged_unique_streams)} 个唯一节目源。")

    # --- 步骤 3: 生成合并后的M3U文件 (未测试) ---
    print("\n--- 步骤 3: 生成合并后的M3U文件 (未测试) ---")
    generate_m3u_file(merged_unique_streams, FINAL_M3U_FILE,
                      header_comment=f"合并所有来源，未测试可用性。生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S JST')}")

    # --- 步骤 4: 检查节目源可用性并生成测试通过的M3U文件 ---
    print("\n--- 步骤 4: 检查节目源可用性并生成测试通过的M3U文件 ---")
    tested_streams = []
    total_streams = len(merged_unique_streams)
    for i, (extinf, url) in enumerate(merged_unique_streams):
        print(f"[{i+1}/{total_streams}] 正在测试 {extinf.split(',')[-1].strip()} - {url[:50]}...", end='\r')
        if check_stream_status(url):
            tested_streams.append((extinf, url))
    print(f"\n测试完成。发现 {len(tested_streams)} 个可用节目源。")

    generate_m3u_file(tested_streams, TESTED_M3U_FILE,
                      header_comment=f"测试通过的可用节目源。生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S JST')}")

    # --- 步骤 5: 更新上次更新时间 ---
    print("\n--- 步骤 5: 更新上次更新时间 ---")
    update_last_update_time()

    print("\n所有操作完成！")

if __name__ == "__main__":
    main()
