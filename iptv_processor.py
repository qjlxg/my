import os
import requests
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置参数 ---
# 存放临时下载的原始M3U文件的目录
DOWNLOAD_DIR = "temp_iptv_sources"
# 合并后的M3U文件路径
MERGED_M3U_FILE = "temp_merged_iptv.m3u"
# 最终输出的有效IPTV节目源文件
FINAL_OUTPUT_FILE = "sc/iptv_list.txt"
# ffprobe 测试流的超时时间 (秒) - 根据网络和服务器性能调整，避免长时间等待
FFPROBE_TIMEOUT = 8 
# 最大并发测试流的数量，根据您的网络和CPU资源调整
MAX_WORKERS = 10 

# --- 辅助函数 ---
def ensure_directory_exists(path):
    """确保目录存在，如果不存在则创建"""
    os.makedirs(path, exist_ok=True)
    print(f"确保目录 '{path}' 存在。")

def download_m3u_file(url, output_path):
    """
    下载M3U/M3U8文件。
    可以使用requests库实现，并添加错误处理和超时。
    """
    try:
        print(f"正在下载: {url} 到 {output_path}...")
        response = requests.get(url, timeout=15)
        response.raise_for_status()  # 检查HTTP错误
        with open(output_path, 'wb') as f:
            f.write(response.content)
        print(f"下载成功: {os.path.basename(output_path)}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"下载失败 {url}: {e}")
        return False
    except Exception as e:
        print(f"处理下载时发生未知错误 {url}: {e}")
        return False

def parse_m3u_content(content):
    """
    解析M3U/M3U8内容，提取EXTINF和URL对。
    返回一个列表，每个元素是一个元组 (extinf_line, url_line)。
    """
    lines = content.splitlines()
    streams = []
    current_extinf = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTINF"):
            current_extinf = line
        elif line.startswith("http"):
            if current_extinf:
                streams.append((current_extinf, line))
                current_extinf = ""  # 重置，避免一个EXTINF对应多个URL
            else:
                # 某些M3U文件可能只有URL没有EXTINF，也加上
                streams.append(("", line)) 
    return streams

def merge_m3u_files_and_deduplicate(input_dir, output_file):
    """
    合并指定目录下的所有M3U文件，并进行去重。
    这里实现了简单的行去重，更高级的去重可以参考 hmlendea/iptv-playlist-aggregator 的逻辑。
    """
    print(f"\n--- 步骤 2: 合并并去重M3U文件 ---")
    merged_streams_set = set() # 用set来去重
    
    ensure_directory_exists(os.path.dirname(output_file))

    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write("#EXTM3U\n") # M3U 文件的开头

        for filename in os.listdir(input_dir):
            if filename.endswith(".m3u") or filename.endswith(".m3u8"):
                filepath = os.path.join(input_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                        content = infile.read()
                        parsed_streams = parse_m3u_content(content)
                        for extinf, url in parsed_streams:
                            # 简单的组合去重，更智能的去重可能需要解析extinf中的channel name
                            stream_key = f"{extinf}|{url}" 
                            if stream_key not in merged_streams_set:
                                merged_streams_set.add(stream_key)
                                if extinf:
                                    outfile.write(extinf + "\n")
                                outfile.write(url + "\n")
                except Exception as e:
                    print(f"读取或解析文件 {filepath} 时发生错误: {e}")
    
    print(f"合并后的文件已保存到: {output_file}")
    # 将 merged_streams_set 转换回 (extinf, url) 元组列表以便后续测试
    streams_to_return = []
    for key in merged_streams_set:
        parts = key.split('|', 1)
        if len(parts) == 2:
            streams_to_return.append((parts[0], parts[1]))
        else:
            streams_to_return.append(("", parts[0]))
    return streams_to_return


def check_stream_availability(stream_tuple):
    """
    使用ffprobe检查IPTV流的可用性。
    返回 (原始的extinf行, 原始的url行, 是否可用布尔值)
    """
    extinf, url = stream_tuple
    try:
        # -v quiet: 静默模式
        # -timeout: 设置连接超时时间 (微秒)
        # -probesize: 探测数据大小 (字节)
        # -select_streams v: 只选择视频流进行探测
        # -show_entries stream=codec_name: 打印视频流的编解码器名称（如果成功探测到）
        # -of default=noprint_wrappers=1:nokey=1: 简化输出格式
        cmd = [
            'ffprobe', '-v', 'quiet', 
            '-timeout', str(FFPROBE_TIMEOUT * 1_000_000), 
            '-probesize', '1000000', 
            '-select_streams', 'v', 
            '-show_entries', 'stream=codec_name', 
            '-of', 'default=noprint_wrappers=1:nokey=1', 
            url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=FFPROBE_TIMEOUT + 2) # 整体运行超时，比 ffprobe 探测超时略长
        
        # 如果ffprobe返回码为0且标准错误中没有明显错误信息，通常认为流可用
        if result.returncode == 0 and "error" not in result.stderr.lower():
            return extinf, url, True
        else:
            # 可以根据需要打印 ffprobe 的详细错误输出用于调试
            # print(f"DEBUG: ffprobe failed for {url}: RC={result.returncode}, Stderr={result.stderr.strip()}")
            return extinf, url, False
    except FileNotFoundError:
        print("\n错误: ffprobe 未找到。请确保已安装 FFmpeg 并将其添加到 PATH 中。跳过流测试。")
        return extinf, url, False
    except subprocess.TimeoutExpired:
        # print(f"DEBUG: ffprobe timeout for {url}")
        return extinf, url, False
    except Exception as e:
        print(f"\n测试 {url} 时发生未知错误: {e}")
        return extinf, url, False

# --- 主逻辑 ---
def main():
    print("--- 欢迎使用IPTV节目源自动化处理工具 ---")

    # --- 步骤 1: 自动获取/下载原始IPTV节目源 ---
    print("\n--- 步骤 1: 获取/下载原始IPTV节目源 ---")
    ensure_directory_exists(DOWNLOAD_DIR)
    
    # 策略 A: 从知名的GitHub仓库获取M3U列表
    # 这些仓库通常会定期更新免费的IPTV列表，您可以直接下载其raw文件。
    # 您可以在这里添加或移除您希望获取的M3U URL
    github_m3u_urls = [
        "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/cn.m3u", # 示例：中国频道
        "https://raw.githubusercontent.com/iptv-org/iptv/master/streams/us.m3u", # 示例：美国频道
        "https://raw.githubusercontent.com/fanmingming/live/main/live.m3u" # 另一个流行的M3U仓库
        # 更多示例：
        # "https://raw.githubusercontent.com/Blackeaglez/IPTV/main/All.m3u",
        # "https://raw.githubusercontent.com/free-iptv/free-iptv-live/master/channels.m3u"
    ]
    
    downloaded_files_count = 0
    for i, url in enumerate(github_m3u_urls):
        output_file_path = os.path.join(DOWNLOAD_DIR, f"github_list_{i}.m3u")
        if download_m3u_file(url, output_file_path):
            downloaded_files_count += 1
        time.sleep(1) # 礼貌性延迟，避免请求过快被服务器拒绝

    print(f"已下载 {downloaded_files_count} 个原始M3U文件到 '{DOWNLOAD_DIR}'。")

    # --- 步骤 2: 合并并去重M3U文件 ---
    streams_to_test = merge_m3u_files_and_deduplicate(DOWNLOAD_DIR, MERGED_M3U_FILE)
    
    if not streams_to_test:
        print("没有可供测试的流，程序终止。")
        return

    # --- 步骤 3 & 4: 测试节目源可用性并输出有效节目源 ---
    print(f"\n--- 步骤 3 & 4: 测试 {len(streams_to_test)} 个节目源并保存有效流 ---")
    ensure_directory_exists(os.path.dirname(FINAL_OUTPUT_FILE))
    
    valid_streams = []
    checked_count = 0

    # 使用线程池并发测试，提高效率
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有测试任务
        future_to_stream = {executor.submit(check_stream_availability, stream): stream for stream in streams_to_test}

        for future in as_completed(future_to_stream):
            original_stream_tuple = future_to_stream[future]
            try:
                extinf, url, is_available = future.result()
                checked_count += 1
                
                status = "可用" if is_available else "不可用"
                # 清除当前行并打印更新的状态，使用 '\r' 实现进度条效果
                print(f"\r[{checked_count}/{len(streams_to_test)}] {status}: {url[:70]}...", end='') 
                
                if is_available:
                    valid_streams.append(f"{extinf}\n{url}")
            except Exception as exc:
                checked_count += 1
                print(f"\r[{checked_count}/{len(streams_to_test)}] 错误: {original_stream_tuple[1][:70]}... 生成异常: {exc}", end='')

    # 打印最终完成信息，确保新行
    print(f"\n\n所有节目源测试完成。")

    with open(FINAL_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("#EXTM3U\n") # M3U 文件的开头
        for stream_entry in valid_streams:
            f.write(stream_entry + "\n")
    
    print(f"共发现 {len(valid_streams)} 个可用流，已保存到: '{FINAL_OUTPUT_FILE}'")

    # --- 清理临时文件 (可选) ---
    print(f"\n--- 清理临时文件 ---")
    try:
        if os.path.exists(DOWNLOAD_DIR):
            import shutil
            shutil.rmtree(DOWNLOAD_DIR)
            print(f"已删除临时下载目录: '{DOWNLOAD_DIR}'")
        if os.path.exists(MERGED_M3U_FILE):
            os.remove(MERGED_M3U_FILE)
            print(f"已删除临时合并文件: '{MERGED_M3U_FILE}'")
    except Exception as e:
        print(f"清理临时文件时发生错误: {e}")

if __name__ == "__main__":
    main()
