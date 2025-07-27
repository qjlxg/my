import os
import requests
from urllib.parse import urlparse
import re
from datetime import datetime # 只需要 datetime 模块，不再需要 pytz
import subprocess # 用于调用外部命令，如 ffprobe

# --- 配置 (已移除 GitHub 仓库信息) ---
# 输出文件路径
OUTPUT_DIR = "output"
FINAL_M3U_FILE = os.path.join(OUTPUT_DIR, "merged_live.m3u")
TESTED_M3U_FILE = os.path.join(OUTPUT_DIR, "tested_live.m3u")
LAST_UPDATE_FILE = os.path.join(OUTPUT_DIR, "last_update.txt") # 记录上次更新时间的文件

# IPTV 节目源列表 (从 GitHub 原始链接下载的 M3U/M3U8 文件)
github_m3u_urls = [
    "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/cn.m3u", # 示例：中国频道
    "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/us.m3u", # 示例：美国频道
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/iptv_list.txt",
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/list.txt"
    # 您可以在这里添加更多有效的 IPTV 源
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
            parts = line.split(',', 1) # 只分割一次，避免频道名称中包含逗号的问题
            if len(parts) == 2 and parts[1].strip().startswith("http"):
                channel_name = parts[0].strip()
                url = parts[1].strip()
                # 将其转换为标准的 #EXTINF 格式，以便后续处理
                synthetic_extinf = f"#EXTINF:-1,{channel_name}"
                streams.append((synthetic_extinf, url))
                current_extinf = "" # 重置，避免影响下一行
    return streams

def merge_and_deduplicate_streams(all_streams):
    """合并并去重节目流，优先保留原始 EXTINF 信息，按 URL 去重"""
    seen_urls = set()
    unique_streams = []
    url_to_extinf = {} # 存储每个 URL 对应的 EXTINF 行，保留第一次遇到的

    for extinf, url in all_streams:
        if url not in seen_urls:
            seen_urls.add(url)
            # 如果是空EXTINF，尝试从URL中提取频道名作为EXTINF的title
            if not extinf:
                parsed_url = urlparse(url)
                path_segments = [s for s in parsed_url.path.split('/') if s]
                if path_segments:
                    name_from_url = os.path.splitext(path_segments[-1])[0]
                    extinf = f"#EXTINF:-1,{name_from_url}"
                else:
                    extinf = "#EXTINF:-1,未知频道"
            
            if url not in url_to_extinf:
                url_to_extinf[url] = extinf
            
    for url, extinf in url_to_extinf.items():
        unique_streams.append((extinf, url))

    return unique_streams

def check_stream_status_deep(url, timeout=10):
    """
    使用 ffprobe 更深入地检查 IPTV 流是否为有效的视频/音频流。
    需要 FFmpeg (包含 ffprobe) 安装在系统 PATH 中。
    """
    try:
        # 构建 ffprobe 命令
        command = [
            "ffprobe",
            "-loglevel", "quiet", # 不打印 ffprobe 的详细输出
            "-select_streams", "v:0", # 尝试获取第一个视频流
            "-show_entries", "stream=codec_type",
            "-of", "default=noprint_wrappers=1:nokey=1", # 简洁输出格式
            "-read_packets", "10", # 只读取少量数据包，快速判断
            "-i", url
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False # 不抛出异常，我们自己检查 returncode
        )

        # ffprobe 成功找到视频流通常会返回 0 且输出 'video' 或 'audio'
        if process.returncode == 0:
            if "video" in process.stdout or "audio" in process.stdout:
                return True
            elif not process.stderr:
                return True
            else:
                return False
        else:
            return False

    except FileNotFoundError:
        log_error("ffprobe 未找到。请确保 FFmpeg (包含 ffprobe) 已安装并添加到 PATH。")
        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        log_error(f"ffprobe 检查 {url} 时发生未知错误: {e}")
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
    """更新上次更新时间文件 (将只显示 UTC 时间)"""
    now_utc = datetime.utcnow() # 使用 UTC 时间
    with open(LAST_UPDATE_FILE, "w", encoding="utf-8") as f:
        f.write(f"Last updated (UTC): {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
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
                      header_comment=f"合并所有来源，未测试可用性。生成时间: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # --- 步骤 4: 检查节目源可用性并生成测试通过的M3U文件 (使用 ffprobe) ---
    print("\n--- 步骤 4: 检查节目源可用性并生成测试通过的M3U文件 (使用 ffprobe 深度测试) ---")
    tested_streams = []
    total_streams = len(merged_unique_streams)
    for i, (extinf, url) in enumerate(merged_unique_streams):
        print(f"[{i+1}/{total_streams}] 正在深度测试 {extinf.split(',')[-1].strip()} - {url[:60]}...", end='\r')
        if check_stream_status_deep(url):
            tested_streams.append((extinf, url))
    print(f"\n深度测试完成。发现 {len(tested_streams)} 个可用节目源。")

    generate_m3u_file(tested_streams, TESTED_M3U_FILE,
                      header_comment=f"测试通过的可用节目源。生成时间: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} (深度测试)")

    # --- 5: 更新上次更新时间 ---
    print("\n--- 步骤 5: 更新上次更新时间 ---")
    update_last_update_time()

    print("\n所有操作完成！")

if __name__ == "__main__":
    main()
