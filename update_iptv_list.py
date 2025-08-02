import os
import re
import subprocess
import socket
import time
from datetime import datetime, timedelta
import logging
import logging.handlers
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import json
import hashlib
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import yaml
import base64
import psutil
from cachetools import TTLCache
import threading

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    [cite_start]"""配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大 [cite: 1]
    参数:
        [cite_start]config: 配置文件字典，包含日志级别和日志文件路径 [cite: 1]
    返回:
        [cite_start]配置好的日志记录器 [cite: 1]
    """
    [cite_start]log_level = getattr(logging, config['logging']['log_level'], logging.INFO) [cite: 1]
    [cite_start]log_file = config['logging']['log_file'] [cite: 1]
    [cite_start]os.makedirs(os.path.dirname(log_file), exist_ok=True) [cite: 1]
    
    [cite_start]logger = logging.getLogger() [cite: 2]
    [cite_start]logger.setLevel(log_level) [cite: 2]
    
    # [cite_start]文件处理器，支持日志文件轮转，最大10MB，保留5个备份 [cite: 2]
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    [cite_start]) [cite: 2]
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    [cite_start])) [cite: 2]
    
    # [cite_start]控制台处理器 [cite: 2]
    [cite_start]console_handler = logging.StreamHandler() [cite: 2]
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    [cite_start])) [cite: 2]
    
    [cite_start]logger.handlers = [file_handler, console_handler] [cite: 3]
    [cite_start]return logger [cite: 3]

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    [cite_start]"""加载并解析 YAML 配置文件 [cite: 3]
    参数:
        [cite_start]config_path: 配置文件路径，默认为 'config/config.yaml' [cite: 3]
    返回:
        [cite_start]解析后的配置字典 [cite: 3]
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            [cite_start]config = yaml.safe_load(file) [cite: 3]
            logging.info("配置文件 config.yaml 加载成功")
        [cite_start]return config [cite: 4]
    except FileNotFoundError:
        [cite_start]logging.error(f"错误：未找到配置文件 '{config_path}'") [cite: 4]
        [cite_start]exit(1) [cite: 4]
    except yaml.YAMLError as e:
        [cite_start]logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}") [cite: 4]
        [cite_start]exit(1) [cite: 4]
    except Exception as e:
        [cite_start]logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}") [cite: 4]
        [cite_start]exit(1) [cite: 4]

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.error("错误：未设置环境变量 'BOT'")
    exit(1)

# 从配置中获取文件路径
# [cite_start]URLS_PATH: 存储 IPTV 源 URL 的文件路径 [cite: 5]
# [cite_start]URL_STATES_PATH: 存储 URL 状态的文件路径 [cite: 5]
# [cite_start]IPTV_LIST_PATH: 最终 IPTV 列表文件路径 [cite: 5]
[cite_start]URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt') [cite: 5]
[cite_start]URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json') [cite: 5]
[cite_start]IPTV_LIST_PATH = CONFIG['output']['paths']['final_iptv_file'] [cite: 5]

# GitHub API 基础 URL
GITHUB_RAW_CONTENT_BASE_URL = "https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main"
GITHUB_API_CONTENTS_BASE_URL = "https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents"
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 初始化缓存
[cite_start]if CONFIG['url_state']['cache_enabled']: [cite: 5]
    [cite_start]os.makedirs(CONFIG['url_state']['cache_dir'], exist_ok=True) [cite: 5]
    [cite_start]content_cache = TTLCache(maxsize=1000, ttl=CONFIG['url_state']['cache_ttl']) [cite: 5]

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    [cite_start]"User-Agent": "Mozilla/5.0 (Windows NT 10.0; [cite: 5] [cite_start]Win64; x64) AppleWebKit/537.36" [cite: 6]
})
[cite_start]pool_size = CONFIG['network']['requests_pool_size'] [cite: 6]
retry_strategy = Retry(
    [cite_start]total=3,  # 增加重试次数 [cite: 6]
    [cite_start]backoff_factor=CONFIG['network']['requests_retry_backoff_factor'], [cite: 6]
    [cite_start]status_forcelist=[429, 500, 502, 503, 504], [cite: 6]
    [cite_start]allowed_methods=["HEAD", "GET", "OPTIONS"] [cite: 6]
)
adapter = HTTPAdapter(
    pool_connections=pool_size,
    pool_maxsize=pool_size,
    max_retries=retry_strategy
[cite_start]) [cite: 6]
[cite_start]session.mount("http://", adapter) [cite: 6]
[cite_start]session.mount("https://", adapter) [cite: 6]

# 性能监控装饰器
def performance_monitor(func):
    [cite_start]"""记录函数执行时间的装饰器，用于性能分析 [cite: 6]
    参数:
        [cite_start]func: 被装饰的函数 [cite: 6]
    返回:
        [cite_start]包装后的函数，记录执行时间 [cite: 6]
    """
    [cite_start]if not CONFIG['performance_monitor']['enabled']: [cite: 6]
        return func
    [cite_start]def wrapper(*args, **kwargs): [cite: 7]
        [cite_start]start_time = time.time() [cite: 7]
        [cite_start]result = func(*args, **kwargs) [cite: 7]
        [cite_start]elapsed_time = time.time() - start_time [cite: 7]
        [cite_start]logging.info(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒") [cite: 7]
        [cite_start]return result [cite: 7]
    [cite_start]return wrapper [cite: 7]

# --- GitHub 文件操作函数 ---
@performance_monitor
def fetch_from_github(file_path_in_repo):
    [cite_start]"""从 GitHub 仓库获取文件内容 [cite: 7]
    参数:
        [cite_start]file_path_in_repo: 仓库中的文件路径 [cite: 7]
    返回:
        文件内容字符串，或 None（如果失败）
    [cite_start]""" [cite: 8]
    [cite_start]raw_url = f"{GITHUB_RAW_CONTENT_BASE_URL}/{file_path_in_repo}" [cite: 8]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 8]
    try:
        [cite_start]response = session.get(raw_url, headers=headers, timeout=10) [cite: 8]
        [cite_start]response.raise_for_status() [cite: 8]
        [cite_start]return response.text [cite: 8]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"错误：从 GitHub 获取 {file_path_in_repo} 失败: {e}") [cite: 8]
        [cite_start]return None [cite: 8]

@performance_monitor
def get_current_sha(file_path_in_repo):
    [cite_start]"""获取 GitHub 仓库中文件的当前 SHA 值 [cite: 8]
    参数:
        [cite_start]file_path_in_repo: 仓库中的文件路径 [cite: 9]
    返回:
        [cite_start]文件的 SHA 值，或 None（如果失败） [cite: 9]
    """
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 9]
    [cite_start]headers = {"Authorization": f"token {GITHUB_TOKEN}"} [cite: 9]
    try:
        [cite_start]response = session.get(api_url, headers=headers, timeout=10) [cite: 9]
        [cite_start]response.raise_for_status() [cite: 9]
        [cite_start]return response.json().get('sha') [cite: 9]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.info(f"获取 {file_path_in_repo} 的 SHA 值失败（可能不存在）: {e}") [cite: 9]
        [cite_start]return None [cite: 9]

@performance_monitor
def save_to_github(file_path_in_repo, content, commit_message):
    [cite_start]"""保存内容到 GitHub 仓库（创建或更新） [cite: 9, 10]
    参数:
        [cite_start]file_path_in_repo: 仓库中的文件路径 [cite: 10]
        [cite_start]content: 要保存的内容 [cite: 10]
        [cite_start]commit_message: 提交信息 [cite: 10]
    返回:
        [cite_start]布尔值，表示保存是否成功 [cite: 10]
    """
    [cite_start]api_url = f"{GITHUB_API_CONTENTS_BASE_URL}/{file_path_in_repo}" [cite: 10]
    [cite_start]sha = get_current_sha(file_path_in_repo) [cite: 10]
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    [cite_start]} [cite: 10]
    [cite_start]encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8') [cite: 10]
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    [cite_start]} [cite: 11]
    if sha:
        [cite_start]payload["sha"] = sha [cite: 11]
    try:
        [cite_start]response = session.put(api_url, headers=headers, json=payload) [cite: 11]
        [cite_start]response.raise_for_status() [cite: 11]
        [cite_start]return True [cite: 11]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"错误：保存 [cite: 11] [cite_start]{file_path_in_repo} 到 GitHub 失败: {e}") [cite: 12]
        [cite_start]return False [cite: 12]

# --- 本地文件操作函数 ---
@performance_monitor
def read_txt_to_array_local(file_name):
    [cite_start]"""从本地 TXT 文件读取内容到数组 [cite: 12]
    参数:
        [cite_start]file_name: 文件路径 [cite: 12]
    返回:
        [cite_start]包含文件每行内容的列表 [cite: 12]
    """
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            [cite_start]lines = [line.strip() for line in file if line.strip()] [cite: 12]
        [cite_start]return lines [cite: 12]
    [cite_start]except FileNotFoundError: [cite: 13]
        [cite_start]logging.warning(f"文件 '{file_name}' 未找到") [cite: 13]
        [cite_start]return [] [cite: 13]
    except Exception as e:
        [cite_start]logging.error(f"读取文件 '{file_name}' 失败: {e}") [cite: 13]
        [cite_start]return [] [cite: 13]

@performance_monitor
def read_existing_channels(file_path):
    [cite_start]"""读取现有频道以进行去重 [cite: 13]
    参数:
        [cite_start]file_path: 频道文件路径 [cite: 13]
    返回:
        [cite_start]包含现有频道名称和 URL 的集合 [cite: 13]
    """
    [cite_start]existing_channels = set() [cite: 13]
    try:
        [cite_start]with open(file_path, 'r', encoding='utf-8') as file: [cite: 14]
            for line in file:
                [cite_start]line = line.strip() [cite: 14]
                [cite_start]if line and ',' in line and not line.startswith('#'): [cite: 14]
                    [cite_start]parts = line.split(',', 1) [cite: 14]
                    [cite_start]if len(parts) == 2: [cite: 15]
                        [cite_start]existing_channels.add((parts[0].strip(), parts[1].strip())) [cite: 15]
    except FileNotFoundError:
        pass
    except Exception as e:
        [cite_start]logging.error(f"读取文件 '{file_path}' 进行去重失败: {e}") [cite: 15]
    [cite_start]return existing_channels [cite: 15]

@performance_monitor
def write_sorted_channels_to_file(file_path, data_list):
    [cite_start]"""将排序后的频道数据写入文件，去重 [cite: 15]
    参数:
        [cite_start]file_path: 输出文件路径 [cite: 15]
        [cite_start]data_list: 包含频道数据的列表 [cite: 16]
    """
    [cite_start]existing_channels = read_existing_channels(file_path) [cite: 16]
    [cite_start]new_channels = set() [cite: 16]
    for _, line in data_list:
        if ',' in line:
            [cite_start]name, url = line.split(',', 1) [cite: 16]
            [cite_start]new_channels.add((name.strip(), url.strip())) [cite: 16]
    [cite_start]all_channels = existing_channels | new_channels [cite: 17]
    try:
        [cite_start]os.makedirs(os.path.dirname(file_path), exist_ok=True) [cite: 17]
        with open(file_path, 'w', encoding='utf-8') as file:
            for name, url in sorted(all_channels, key=lambda x: x[0]):
                [cite_start]file.write(f"{name},{url}\n") [cite: 17]
        [cite_start]logging.info(f"写入 {len(all_channels)} 个频道到 {file_path}") [cite: 17]
    except Exception as e:
        [cite_start]logging.error(f"写入文件 '{file_path}' 失败: {e}") [cite: 17]

# --- URL 处理和频道提取函数 ---
@performance_monitor
def get_url_file_extension(url):
    [cite_start]"""获取 [cite: 17] [cite_start]URL 的文件扩展名 [cite: 18]
    参数:
        [cite_start]url: 要解析的 URL [cite: 18]
    返回:
        [cite_start]文件扩展名（小写），或空字符串（如果失败） [cite: 18]
    """
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 18]
        [cite_start]return os.path.splitext(parsed_url.path)[1].lower() [cite: 18]
    except ValueError as e:
        [cite_start]logging.info(f"获取 URL 扩展名失败: {url} - {e}") [cite: 18]
        [cite_start]return "" [cite: 18]

@performance_monitor
def convert_m3u_to_txt(m3u_content):
    [cite_start]"""将 M3U 格式转换为 TXT 格式（频道名称，URL） [cite: 18]
    参数:
        [cite_start]m3u_content: M3U 文件内容 [cite: 19]
    返回:
        [cite_start]转换后的 TXT 格式字符串 [cite: 19]
    """
    [cite_start]lines = m3u_content.split('\n') [cite: 19]
    [cite_start]txt_lines = [] [cite: 19]
    [cite_start]channel_name = "未知频道" [cite: 19]
    for line in lines:
        [cite_start]line = line.strip() [cite: 19]
        [cite_start]if not line or line.startswith('#EXTM3U'): [cite: 19]
            continue
        [cite_start]if line.startswith('#EXTINF'): [cite: 20]
            [cite_start]match = re.search(r'#EXTINF:.*?\,(.*)', line, re.IGNORECASE) [cite: 20]
            [cite_start]channel_name = match.group(1).strip() or "未知频道" if match else "未知频道" [cite: 20]
        [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'): [cite: 20]
            [cite_start]txt_lines.append(f"{channel_name},{line}") [cite: 20]
        [cite_start]channel_name = "未知频道" [cite: 20]
    [cite_start]return '\n'.join(txt_lines) [cite: 20]

@performance_monitor
def clean_url_params(url):
    [cite_start]"""清理 URL 参数，仅保留方案、网络位置和路径 [cite: 20]
    参数:
        [cite_start]url: 要清理的 URL [cite: 21]
    返回:
        [cite_start]清理后的 URL 字符串 [cite: 21]
    """
    try:
        [cite_start]parsed_url = urlparse(url) [cite: 21]
        [cite_start]return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path [cite: 21]
    except ValueError as e:
        [cite_start]logging.info(f"清理 URL 参数失败: {url} - {e}") [cite: 21]
        [cite_start]return url [cite: 21]

@performance_monitor
def extract_channels_from_url(url, url_states, source_tracker):
    [cite_start]"""从 URL 提取频道，支持多种文件格式 [cite: 21]
    参数:
        [cite_start]url: 要提取频道的 URL [cite: 22]
        [cite_start]url_states: URL 状态字典 [cite: 22]
        [cite_start]source_tracker: 跟踪频道来源的字典 [cite: 22]
    返回:
        [cite_start]提取的频道列表 [cite: 22]
    """
    [cite_start]extracted_channels = [] [cite: 22]
    try:
        [cite_start]start_time = time.time() [cite: 22]
        [cite_start]text = fetch_url_content_with_retry(url, url_states) [cite: 22]
        if text is None:
            [cite_start]logging.info(f"URL {url} 无新内容或获取失败，跳过") [cite: 22]
            [cite_start]return [] [cite: 22]

        [cite_start]extension = get_url_file_extension(url).lower() [cite: 23]
        [cite_start]if extension in [".m3u", ".m3u8"]: [cite: 23]
            [cite_start]text = convert_m3u_to_txt(text) [cite: 23]
        [cite_start]elif extension in [".ts", ".flv", ".mp4", ".hls", ".dash"]: [cite: 23]
            [cite_start]channel_name = f"Stream_{os.path.basename(urlparse(url).path)}" [cite: 23]
            [cite_start]if pre_screen_url(url): [cite: 23]
                [cite_start]extracted_channels.append((channel_name, url)) [cite: 23]
                [cite_start]source_tracker[(channel_name, url)] = url [cite: 24]
                [cite_start]logging.info(f"提取单一流: {channel_name},{url}") [cite: 24]
            [cite_start]return extracted_channels [cite: 24]
        [cite_start]elif extension not in [".txt", ".csv"]: [cite: 24]
            [cite_start]logging.info(f"不支持的文件扩展名: {url}") [cite: 24]
            [cite_start]return [] [cite: 24]

        [cite_start]lines = text.split('\n') [cite: 24]
        [cite_start]channel_count = 0 [cite: 24]
        [cite_start]for line in lines: [cite: 25]
            [cite_start]line = line.strip() [cite: 25]
            [cite_start]if not line or line.startswith('#'): [cite: 25]
                continue
            [cite_start]if "," in line and "://" in line: [cite: 25]
                [cite_start]parts = line.split(',', 1) [cite: 25]
                [cite_start]if len(parts) != 2: [cite: 26]
                    [cite_start]logging.info(f"跳过无效频道行（格式错误）: {line}") [cite: 26]
                    continue
                [cite_start]channel_name, channel_address_raw = parts [cite: 26]
                [cite_start]channel_name = channel_name.strip() or "未知频道" [cite: 26]
                [cite_start]channel_address_raw = channel_address_raw.strip() [cite: 27]

                [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw): [cite: 27]
                    [cite_start]logging.info(f"跳过无效频道 URL（无有效协议）: {line}") [cite: 27]
                    continue

                [cite_start]if '#' in channel_address_raw: [cite: 28]
                    [cite_start]url_list = channel_address_raw.split('#') [cite: 28]
                    for channel_url in url_list:
                        [cite_start]channel_url = clean_url_params(channel_url.strip()) [cite: 28]
                        [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 28, 29]
                            [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 29]
                            [cite_start]source_tracker[(channel_name, channel_url)] = url [cite: 29]
                            [cite_start]channel_count += 1 [cite: 29]
                        else:
                            [cite_start]logging.info(f"跳过无效或预筛选失败的频道 URL: {channel_url}") [cite: 30]
                else:
                    [cite_start]channel_url = clean_url_params(channel_address_raw) [cite: 30]
                    [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 30, 31]
                        [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 31]
                        [cite_start]source_tracker[(channel_name, channel_url)] = url [cite: 31]
                        [cite_start]channel_count += 1 [cite: 31]
                    else:
                        [cite_start]logging.info(f"跳过无效或预筛选失败的频道 URL: {channel_url}") [cite: 32]
            [cite_start]elif re.match(r'^[a-zA-Z0-9+.-]+://', line): [cite: 32]
                [cite_start]channel_name = f"Stream_{channel_count + 1}" [cite: 32]
                [cite_start]channel_url = clean_url_params(line) [cite: 32]
                [cite_start]if channel_url and pre_screen_url(channel_url): [cite: 32, 33]
                    [cite_start]extracted_channels.append((channel_name, channel_url)) [cite: 33]
                    [cite_start]source_tracker[(channel_name, channel_url)] = url [cite: 33]
                    [cite_start]channel_count += 1 [cite: 33]
                else:
                    [cite_start]logging.info(f"跳过无效或预筛选失败的单一 URL: {line}") [cite: 33]
        [cite_start]logging.info(f"成功从 {url} 提取 [cite: 34] [cite_start]{channel_count} 个频道，耗时 {time.time() - start_time:.2f} 秒") [cite: 34]
        [cite_start]return extracted_channels [cite: 34]
    except Exception as e:
        [cite_start]logging.error(f"从 {url} 提取频道失败: {e}") [cite: 34]
        [cite_start]return [] [cite: 34]

# --- URL 状态管理函数 ---
@performance_monitor
def load_url_states_local():
    [cite_start]"""加载 URL 状态并清理过期状态 [cite: 34]
    返回:
        [cite_start]清理后的 URL 状态字典 [cite: 35]
    """
    [cite_start]url_states = {} [cite: 35]
    try:
        [cite_start]with open(URL_STATES_PATH, 'r', encoding='utf-8') as file: [cite: 35]
            [cite_start]url_states = json.load(file) [cite: 35]
    except FileNotFoundError:
        [cite_start]logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态") [cite: 35]
    except json.JSONDecodeError as e:
        [cite_start]logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}") [cite: 35]
        [cite_start]return {} [cite: 35]
    
    [cite_start]current_time = datetime.now() [cite: 35]
    [cite_start]updated_url_states = {} [cite: 35]
    for url, state in url_states.items():
        [cite_start]if 'last_checked' in state: [cite: 35]
            try:
                [cite_start]last_checked_datetime = datetime.fromisoformat(state['last_checked']) [cite: 36]
                [cite_start]if (current_time - last_checked_datetime).days < CONFIG['url_state']['expiration_days']: [cite: 36]
                    [cite_start]updated_url_states[url] = state [cite: 36]
                else:
                    [cite_start]logging.info(f"移除过期 URL 状态: {url}（最后检查于 [cite: 36] [cite_start]{state['last_checked']}）") [cite: 37]
            except ValueError:
                [cite_start]logging.warning(f"无法解析 URL {url} 的 last_checked 时间戳: {state['last_checked']}") [cite: 37]
                [cite_start]updated_url_states[url] = state [cite: 37]
        else:
            [cite_start]updated_url_states[url] = state [cite: 37]
    [cite_start]return updated_url_states [cite: 37]

@performance_monitor
def save_url_states_local(url_states):
    [cite_start]"""保存 URL 状态到本地文件 [cite: 37]
    参数:
        [cite_start]url_states: [cite: 38] [cite_start]URL 状态字典 [cite: 38]
    """
    try:
        [cite_start]os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True) [cite: 38]
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            [cite_start]json.dump(url_states, file, indent=4, ensure_ascii=False) [cite: 38]
    except Exception as e:
        [cite_start]logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}") [cite: 38]

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
def fetch_url_content_with_retry(url, url_states):
    [cite_start]"""带重试机制获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash [cite: 38]
    参数:
        [cite_start]url: 要获取内容的 URL [cite: 39]
        [cite_start]url_states: [cite: 39] [cite_start]URL 状态字典 [cite: 39]
    返回:
        [cite_start]URL 内容，或 None（如果失败或内容未变更） [cite: 39]
    """
    [cite_start]if CONFIG['url_state']['cache_enabled'] and url in content_cache: [cite: 39]
        [cite_start]logging.info(f"从缓存读取 URL 内容: {url}") [cite: 39]
        [cite_start]return content_cache[url] [cite: 39]

    [cite_start]headers = {} [cite: 39]
    [cite_start]current_state = url_states.get(url, {}) [cite: 39]
    [cite_start]if 'etag' in current_state: [cite: 39]
        [cite_start]headers['If-None-Match'] = current_state['etag'] [cite: 40]
    [cite_start]if 'last_modified' in current_state: [cite: 40]
        [cite_start]headers['If-Modified-Since'] = current_state['last_modified'] [cite: 40]

    try:
        # [cite_start]降低超时时间到 10 秒 [cite: 40]
        [cite_start]response = session.get(url, headers=headers, timeout=10) [cite: 40]
        [cite_start]response.raise_for_status() [cite: 40]

        [cite_start]if response.status_code == 304: [cite: 40]
            [cite_start]logging.info(f"URL 内容未变更 (304): {url}") [cite: 40]
            [cite_start]if url not in url_states: [cite: 40]
                [cite_start]url_states[url] = {} [cite: 41]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 41]
            [cite_start]return None [cite: 41]

        [cite_start]content = response.text [cite: 41]
        [cite_start]content_hash = hashlib.md5(content.encode('utf-8')).hexdigest() [cite: 41]

        [cite_start]if 'content_hash' in current_state and current_state['content_hash'] == content_hash: [cite: 41]
            [cite_start]logging.info(f"URL 内容未变更（哈希相同）: {url}") [cite: 42]
            [cite_start]if url not in url_states: [cite: 42]
                [cite_start]url_states[url] = {} [cite: 42]
            [cite_start]url_states[url]['last_checked'] = datetime.now().isoformat() [cite: 42]
            [cite_start]return None [cite: 42]

        url_states[url] = {
            'etag': response.headers.get('ETag'),
            'last_modified': response.headers.get('Last-Modified'),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        [cite_start]} [cite: 42]

        [cite_start]if CONFIG['url_state']['cache_enabled']: [cite: 43]
            [cite_start]content_cache[url] = content [cite: 43]
            [cite_start]cache_file = os.path.join(CONFIG['url_state']['cache_dir'], f"{hashlib.md5(url.encode()).hexdigest()}.txt") [cite: 43]
            with open(cache_file, 'w', encoding='utf-8') as f:
                [cite_start]f.write(content) [cite: 43]

        [cite_start]logging.info(f"成功获取新内容: {url}") [cite: 43]
        [cite_start]return content [cite: 43]
    except requests.exceptions.Timeout:
        [cite_start]logging.error(f"请求 [cite: 43] [cite_start]URL 超时: {url}") [cite: 44]
        [cite_start]return None [cite: 44]
    except requests.exceptions.RequestException as e:
        [cite_start]logging.error(f"请求 URL 失败（重试后）: {url} - {e}") [cite: 44]
        [cite_start]return None [cite: 44]
    except Exception as e:
        [cite_start]logging.error(f"获取 URL 内容未知错误: {url} - {e}") [cite: 44]
        [cite_start]return None [cite: 44]

@performance_monitor
def pre_screen_url(url):
    [cite_start]"""根据配置预筛选 URL（协议、长度、无效模式） [cite: 44]
    参数:
        [cite_start]url: 要筛选的 URL [cite: 45]
    返回:
        [cite_start]布尔值，表示 URL 是否通过筛选 [cite: 45]
    """
    [cite_start]if not isinstance(url, str) or not url: [cite: 45]
        [cite_start]logging.info(f"预筛选过滤（无效类型或空）: {url}") [cite: 45]
        [cite_start]return False [cite: 45]

    [cite_start]if not re.match(r'^[a-zA-Z0-9+.-]+://', url): [cite: 45]
        [cite_start]logging.info(f"预筛选过滤（无有效协议）: {url}") [cite: 45]
        [cite_start]return False [cite: 45]

    [cite_start]if re.search(r'[^\x00-\x7F]', url) or ' ' in url: [cite: 46]
        [cite_start]logging.info(f"预筛选过滤（包含非法字符或空格）: {url}") [cite: 46]
        [cite_start]return False [cite: 46]

    try:
        [cite_start]parsed_url = urlparse(url) [cite: 46]
        [cite_start]if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']: [cite: 46]
            [cite_start]logging.info(f"预筛选过滤（不支持的协议）: {url}") [cite: 46]
            [cite_start]return False [cite: 46]

        [cite_start]if not parsed_url.netloc: [cite: 46]
            [cite_start]logging.info(f"预筛选过滤（无网络位置）: {url}") [cite: 47]
            [cite_start]return False [cite: 47]

        [cite_start]invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns'] [cite: 47]
        [cite_start]compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns] [cite: 47]
        for pattern in compiled_invalid_url_patterns:
            [cite_start]if pattern.search(url): [cite: 47]
                [cite_start]logging.info(f"预筛选过滤（无效模式）: {url}") [cite: 47]
                [cite_start]return False [cite: 47]

        [cite_start]if len(url) < 15: [cite: 47]
            [cite_start]logging.info(f"预筛选过滤（URL 过短）: {url}") [cite: 48]
            [cite_start]return False [cite: 48]

        [cite_start]return True [cite: 48]
    except ValueError as e:
        [cite_start]logging.info(f"预筛选过滤（URL 解析错误）: {url} - {e}") [cite: 48]
        [cite_start]return False [cite: 48]

@performance_monitor
def filter_and_modify_channels(channels):
    [cite_start]"""过滤和修改频道名称及 URL [cite: 48]
    参数:
        [cite_start]channels: 包含频道名称和 URL 的列表 [cite: 48]
    返回:
        [cite_start]过滤和修改后的频道列表 [cite: 48]
    """
    [cite_start]filtered_channels = [] [cite: 48]
    [cite_start]pre_screened_count = 0 [cite: 49]
    for name, url in channels:
        [cite_start]if not pre_screen_url(url): [cite: 49]
            [cite_start]logging.info(f"过滤频道（预筛选失败）: {name},{url}") [cite: 49]
            continue
        [cite_start]pre_screened_count += 1 [cite: 49]

        # [cite_start]应用名称替换 [cite: 49]
        [cite_start]new_name = name [cite: 49]
        [cite_start]for old_str, new_str in CONFIG['channel_name_replacements'].items(): [cite: 49]
            [cite_start]new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE) [cite: 49]
        [cite_start]new_name = new_name.strip() [cite: 49]

        # [cite_start]过滤关键字 [cite: 50]
        [cite_start]if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']): [cite: 50]
            [cite_start]logging.info(f"过滤频道（名称匹配黑名单）: {name},{url}") [cite: 50]
            continue

        [cite_start]filtered_channels.append((new_name, url)) [cite: 50]
    [cite_start]logging.info(f"URL 预筛选后剩余 {pre_screened_count} 个频道进行进一步过滤") [cite: 50]
    [cite_start]return filtered_channels [cite: 50]

# --- 频道有效性检查函数 (已移除网络可达性检查) ---

# --- 文件合并和排序函数 ---
@performance_monitor
def generate_update_time_header():
    [cite_start]"""生成文件顶部更新时间信息 [cite: 73]
    返回:
        [cite_start]包含更新时间和格式的标题行列表 [cite: 74]
    """
    [cite_start]now = datetime.now() [cite: 74]
    return [
        [cite_start]f"更新时间,#genre#\n", [cite: 74]
        [cite_start]f"{now.strftime('%Y-%m-%d %H:%M:%S')},url\n" [cite: 74]
    ]

@performance_monitor
def group_and_limit_channels(lines):
    [cite_start]"""对频道分组并限制每个频道名称下的 URL 数量 [cite: 74]
    参数:
        [cite_start]lines: 频道行列表 [cite: 74]
    返回:
        [cite_start]分组并限制后的频道行列表 [cite: 75]
    """
    [cite_start]grouped_channels = {} [cite: 75]
    for line_content in lines:
        [cite_start]line_content = line_content.strip() [cite: 75]
        [cite_start]if line_content: [cite: 75]
            [cite_start]channel_name = line_content.split(',', 1)[0].strip() [cite: 75]
            if channel_name not in grouped_channels:
                [cite_start]grouped_channels[channel_name] = [] [cite: 75]
            [cite_start]grouped_channels[channel_name].append(line_content) [cite: 75]
    
    [cite_start]final_grouped_lines = [] [cite: 75]
    for channel_name in grouped_channels:
        [cite_start]for ch_line in grouped_channels[channel_name][:CONFIG.get('max_channel_urls_per_group', 100)]: [cite: 75, 76]
            [cite_start]final_grouped_lines.append(ch_line + '\n') [cite: 76]
    [cite_start]return final_grouped_lines [cite: 76]

@performance_monitor
def merge_local_channel_files(local_channels_directory, output_file_name, url_states):
    [cite_start]"""合并本地频道列表文件，去重并清理，按分类输出 [cite: 76]
    参数:
        [cite_start]local_channels_directory: 本地频道文件目录 [cite: 76]
        [cite_start]output_file_name: 输出文件路径 [cite: 76]
        [cite_start]url_states: URL 状态字典 [cite: 76]
    """
    [cite_start]os.makedirs(local_channels_directory, exist_ok=True) [cite: 76]
    [cite_start]existing_channels_data = read_existing_channels(output_file_name) [cite: 76]
    [cite_start]all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')] [cite: 76]
    
    [cite_start]uncategorized_file_in_root = CONFIG['output']['paths']['uncategorized_channels_file'] [cite: 76]
    # Only add uncategorized_file_in_root if it exists
    [cite_start]if os.path.isfile(uncategorized_file_in_root): [cite: 77]
        [cite_start]all_iptv_files_in_dir.append(os.path.basename(uncategorized_file_in_root)) [cite: 77]
    else:
        [cite_start]logging.info(f"未分类文件 '{uncategorized_file_in_root}' 不存在，跳过添加") [cite: 77]

    [cite_start]files_to_merge_paths = [] [cite: 77]
    [cite_start]processed_files = set() [cite: 77]

    # [cite_start]获取所有可能的分类名称（包括别名后的最终分类） [cite: 77]
    [cite_start]all_possible_categories = list(CONFIG.get('ordered_categories', [])) [cite: 77]
    [cite_start]for alias_target in set(CONFIG.get('category_aliases', {}).values()): [cite: 77]
        if alias_target not in all_possible_categories:
            [cite_start]all_possible_categories.append(alias_target) [cite: 78]

    # [cite_start]按照最终的分类顺序，收集需要合并的文件 [cite: 78]
    for category in all_possible_categories:
        [cite_start]file_name = f"{category}_iptv.txt" [cite: 78]
        [cite_start]temp_path = os.path.join(local_channels_directory, file_name) [cite: 78]
        
        [cite_start]if os.path.basename(temp_path) in all_iptv_files_in_dir and temp_path not in processed_files: [cite: 78]
            [cite_start]files_to_merge_paths.append(temp_path) [cite: 78]
            [cite_start]processed_files.add(os.path.basename(temp_path)) [cite: 78]

    # [cite_start]处理未被上面明确分类的文件，如最初的 uncategorized_channels.txt [cite: 78]
    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            [cite_start]full_path = os.path.join(local_channels_directory, [cite: 79] [cite_start]file_name) if file_name != os.path.basename(uncategorized_file_in_root) else uncategorized_file_in_root [cite: 79]
            if os.path.isfile(full_path):
                [cite_start]files_to_merge_paths.append(full_path) [cite: 79]
                [cite_start]processed_files.add(file_name) [cite: 79]
            else:
                [cite_start]logging.info(f"文件 '{full_path}' 不存在，跳过添加") [cite: 79]

    [cite_start]new_channels_from_merged_files = set() [cite: 79]
    for file_path in files_to_merge_paths:
        [cite_start]try: [cite: 80]
            [cite_start]with open(file_path, "r", encoding="utf-8") as file: [cite: 80]
                [cite_start]lines = file.readlines() [cite: 80]
                if not lines:
                    continue
                [cite_start]for line in lines: [cite: 80, 81]
                    [cite_start]line = line.strip() [cite: 81]
                    [cite_start]if line and ',' in line and '#genre#' not in line: [cite: 81]
                        [cite_start]name, url = line.split(',', 1) [cite: 81]
                        [cite_start]new_channels_from_merged_files.add((name.strip(), url.strip())) [cite: 81]
        [cite_start]except FileNotFoundError: [cite: 82]
            [cite_start]logging.warning(f"无法打开文件 '{file_path}'，可能已被删除或路径错误") [cite: 82]
            continue
        except Exception as e:
            [cite_start]logging.error(f"读取文件 '{file_path}' 失败: {e}") [cite: 82]
            continue

    [cite_start]combined_channels = existing_channels_data | new_channels_from_merged_files [cite: 83]
    [cite_start]channels_for_checking_lines = [f"{name},{url}" for name, url in combined_channels] [cite: 83]
    [cite_start]logging.warning(f"总计 {len(channels_for_checking_lines)} 个唯一频道待检查和过滤") [cite: 83]

    # 移除了实际的网络有效性检查，所有通过预筛选和格式检查的频道都被认为是“有效”的
    valid_channels_from_check = [(0, line) for line in channels_for_checking_lines] 

    # [cite_start]按分类重新组织有效频道 [cite: 83]
    categorized_channels_checked, uncategorized_channels_checked, final_ordered_categories_checked = categorize_channels(
        [cite_start][(name, url) for _, line in valid_channels_from_check for name, url in [line.split(',', 1)]] [cite: 84]
    )

    # [cite_start]保存合并后的主文件，按分类输出 [cite: 84]
    try:
        with open(output_file_name, "w", encoding='utf-8') as iptv_list_file:
            [cite_start]iptv_list_file.writelines(generate_update_time_header()) [cite: 84]
            [cite_start]for category in final_ordered_categories_checked: [cite: 84]
                if category in categorized_channels_checked and categorized_channels_checked[category]:
                    [cite_start]iptv_list_file.write(f"{category},#genre#\n") [cite: 84]
                    for name, url in sorted(categorized_channels_checked[category], key=lambda x: x[0]):
                        [cite_start]iptv_list_file.write(f"{name},{url}\n") [cite: 85]
            [cite_start]if uncategorized_channels_checked: [cite: 85]
                [cite_start]iptv_list_file.write("其他频道,#genre#\n") [cite: 85]
                for name, url in sorted(uncategorized_channels_checked, key=lambda x: x[0]):
                    [cite_start]iptv_list_file.write(f"{name},{url}\n") [cite: 85]
        [cite_start]logging.warning(f"所有频道列表文件合并、去重、分类完成，输出保存到: {output_file_name}") [cite: 85]
    except Exception as e:
        [cite_start]logging.error(f"写入文件 '{output_file_name}' [cite: 86] [cite_start]失败: {e}") [cite: 86]

    # [cite_start]保存未分类频道 [cite: 86]
    try:
        [cite_start]os.makedirs(os.path.dirname(uncategorized_file_in_root), exist_ok=True) [cite: 86]
        with open(uncategorized_file_in_root, "w", encoding='utf-8') as uncat_file:
            for name, url in sorted(uncategorized_channels_checked, key=lambda x: x[0]):
                [cite_start]uncat_file.write(f"{name},{url}\n") [cite: 86]
        [cite_start]logging.warning(f"未分类频道保存到: {uncategorized_file_in_root}") [cite: 87]
    except Exception as e:
        [cite_start]logging.error(f"写入未分类文件 '{uncategorized_file_in_root}' 失败: {e}") [cite: 87]

# --- 远程 TXT 文件操作函数 ---
@performance_monitor
def write_array_to_txt_local(file_path, data_array, commit_message=None):
    [cite_start]"""将数组内容写入本地 TXT 文件 [cite: 87]
    参数:
        [cite_start]file_path: 输出文件路径 [cite: 87]
        [cite_start]data_array: 要写入的数据数组 [cite: 87]
        [cite_start]commit_message: GitHub 提交信息（未使用） [cite: 87]
    """
    try:
        [cite_start]os.makedirs(os.path.dirname(file_path), exist_ok=True) [cite: 87]
        with open(file_path, 'w', encoding='utf-8') as file:
            [cite_start]file.write('\n'.join(data_array)) [cite: 88]
        [cite_start]logging.info(f"写入 {len(data_array)} 行到 '{file_path}'") [cite: 88]
    [cite_start]except Exception as e: [cite: 88]
        [cite_start]logging.error(f"写入文件 '{file_path}' 失败: {e}") [cite: 88]

# --- GitHub URL 自动发现函数 ---
@performance_monitor
def auto_discover_github_urls(urls_file_path_local, github_token):
    [cite_start]"""从 GitHub 自动发现新的 IPTV 源 URL [cite: 88]
    参数:
        [cite_start]urls_file_path_local: 本地 URL 文件路径 [cite: 88]
        [cite_start]github_token: GitHub API 令牌 [cite: 88]
    """
    [cite_start]if not github_token: [cite: 88]
        [cite_start]logging.warning("未提供 GitHub token，跳过 URL 自动发现") [cite: 89]
        return

    [cite_start]existing_urls = set(read_txt_to_array_local(urls_file_path_local)) [cite: 89]
    [cite_start]for backup_url in CONFIG.get('backup_urls', []): [cite: 89]
        [cite_start]try: [cite: 89]
            [cite_start]response = session.get(backup_url, timeout=10) [cite: 89]
            [cite_start]response.raise_for_status() [cite: 89]
            [cite_start]existing_urls.update([line.strip() for line in response.text.split('\n') if line.strip()]) [cite: 89]
        except Exception as e:
            [cite_start]logging.warning(f"从备用 URL {backup_url} 获取失败: {e}") [cite: 89]

    [cite_start]found_urls = set() [cite: 89]
    headers = {
        [cite_start]"Accept": "application/vnd.github.v3.text-match+json", [cite: 89]
        [cite_start]"Authorization": f"token {github_token}" [cite: 90]
    [cite_start]} [cite: 90]

    [cite_start]logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL") [cite: 90]
    [cite_start]keyword_url_counts = {keyword: 0 for keyword in CONFIG.get('search_keywords', [])} [cite: 90]

    [cite_start]for i, keyword in enumerate(CONFIG.get('search_keywords', [])): [cite: 90]
        [cite_start]keyword_found_urls = set() [cite: 91]
        if i > 0:
            [cite_start]logging.warning(f"切换到下一个关键词: '{keyword}'，等待 {CONFIG['github']['retry_wait']} 秒以避免速率限制") [cite: 91]
            [cite_start]time.sleep(CONFIG['github']['retry_wait']) [cite: 91]

        [cite_start]page = 1 [cite: 91]
        [cite_start]while page <= CONFIG['github']['max_search_pages']: [cite: 91]
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                [cite_start]"per_page": CONFIG['github']['per_page'], [cite: 92]
                [cite_start]"page": page [cite: 92]
            [cite_start]} [cite: 92]
            try:
                response = session.get(
                    [cite_start]f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}", [cite: 92]
                    [cite_start]headers=headers, [cite: 93]
                    [cite_start]params=params, [cite: 93]
                    [cite_start]timeout=CONFIG['github']['api_timeout'] [cite: 93]
                )
                [cite_start]response.raise_for_status() [cite: 93]
                [cite_start]data = response.json() [cite: 93]

                [cite_start]rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0)) [cite: 94]
                [cite_start]rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0)) [cite: 94]

                [cite_start]if rate_limit_remaining == 0: [cite: 94]
                    [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 94]
                    [cite_start]logging.warning(f"GitHub API 速率限制达到，剩余请求: 0，等待 {wait_seconds:.0f} 秒") [cite: 94]
                    [cite_start]time.sleep(wait_seconds) [cite: 95]
                    [cite_start]continue [cite: 95]

                [cite_start]if not data.get('items'): [cite: 95]
                    [cite_start]logging.info(f"关键词 '{keyword}' 在第 {page} 页无结果") [cite: 95]
                    [cite_start]break [cite: 95]

                [cite_start]for item in data['items']: [cite: 96]
                    [cite_start]html_url = item.get('html_url', '') [cite: 96]
                    [cite_start]raw_url = None [cite: 96]
                    [cite_start]match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url) [cite: 96]
                    [cite_start]if match: [cite: 97]
                        [cite_start]user, repo, branch, file_path = match.groups() [cite: 97]
                        [cite_start]raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}" [cite: 97]
                    else:
                        [cite_start]logging.info(f"无法解析 raw URL: {html_url}") [cite: 98]
                        [cite_start]continue [cite: 98]

                    [cite_start]if raw_url and raw_url not in existing_urls and raw_url not in found_urls: [cite: 98]
                        try:
                            [cite_start]content_response = session.get(raw_url, timeout=5) [cite: 99]
                            [cite_start]content_response.raise_for_status() [cite: 99]
                            [cite_start]content = content_response.text [cite: 99]
                            [cite_start]if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u|txt|csv|ts|flv|mp4|hls|dash)$', raw_url, re.IGNORECASE): [cite: 100]
                                [cite_start]found_urls.add(raw_url) [cite: 100]
                                [cite_start]keyword_found_urls.add(raw_url) [cite: 100]
                                [cite_start]logging.info(f"发现新的 IPTV 源 URL: {raw_url}") [cite: 101]
                            else:
                                [cite_start]logging.info(f"URL {raw_url} 不包含 M3U 内容或不支持的文件扩展名，跳过") [cite: 101]
                        [cite_start]except requests.exceptions.RequestException as req_e: [cite: 101]
                            [cite_start]logging.info(f"获取 {raw_url} 内容失败: {req_e}") [cite: 102]
                        except Exception as exc:
                            [cite_start]logging.info(f"检查 {raw_url} 内容时发生意外错误: {exc}") [cite: 102]

                [cite_start]logging.info(f"完成关键词 '{keyword}' 第 {page} 页，发现 {len(keyword_found_urls)} 个新 URL") [cite: 103]
                [cite_start]page += 1 [cite: 103]

            except requests.exceptions.RequestException as e:
                [cite_start]if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403: [cite: 103]
                    [cite_start]logging.error(f"GitHub API 速率限制或访问被拒绝，关键词 '{keyword}': {e}") [cite: 103]
                    [cite_start]if rate_limit_remaining == 0: [cite: 104]
                        [cite_start]wait_seconds = max(0, rate_limit_reset - time.time()) + 5 [cite: 104]
                        [cite_start]logging.warning(f"关键词 '{keyword}' 速率限制，等待 {wait_seconds:.0f} 秒") [cite: 104]
                        [cite_start]time.sleep(wait_seconds) [cite: 104]
                        [cite_start]continue [cite: 105]
                else:
                    [cite_start]logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}") [cite: 105]
                break
            [cite_start]except Exception as e: [cite: 105]
                [cite_start]logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}") [cite: 106]
                break
        [cite_start]keyword_url_counts[keyword] = len(keyword_found_urls) [cite: 106]

    [cite_start]if found_urls: [cite: 106]
        [cite_start]updated_urls = sorted(list(existing_urls | found_urls)) [cite: 107]
        [cite_start]logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL") [cite: 107]
        [cite_start]write_array_to_txt_local(urls_file_path_local, updated_urls) [cite: 107]
    else:
        [cite_start]logging.warning("未发现新的 IPTV 源 URL") [cite: 107]

    [cite_start]for keyword, count in keyword_url_counts.items(): [cite: 107]
        [cite_start]logging.warning(f"关键词 '{keyword}' 发现 {count} 个新 URL") [cite: 108]

# --- URL 清理函数 ---
@performance_monitor
def cleanup_urls_local(urls_file_path_local, url_states):
    [cite_start]"""清理无效或失败的 URL (注意: 移除了网络有效性检查后，此函数中基于'stream_fail_count'和'stream_check_failed_at'的清理将不再生效，因为这些状态不再更新。) [cite: 108]
    参数:
        [cite_start]urls_file_path_local: 本地 URL 文件路径 [cite: 108]
        [cite_start]url_states: URL 状态字典 [cite: 108]
    """
    [cite_start]all_urls = read_txt_to_array_local(urls_file_path_local) [cite: 108]
    [cite_start]current_time = datetime.now() [cite: 108]
    [cite_start]urls_to_keep = [] [cite: 108]
    [cite_start]removed_count = 0 [cite: 108]

    for url in all_urls:
        [cite_start]state = url_states.get(url, {}) [cite: 109]
        [cite_start]fail_count = state.get('stream_fail_count', 0) [cite: 109]
        [cite_start]last_failed_time_str = state.get('stream_check_failed_at') [cite: 109]
        [cite_start]remove_url = False [cite: 109]

        # 以下逻辑在移除了网络可达性检查后，将不再触发对 URL 的移除，因为 'stream_fail_count' 和 'stream_check_failed_at' 不会被更新。
        [cite_start]if fail_count > CONFIG['channel_retention']['url_fail_threshold']: [cite: 109]
            [cite_start]if last_failed_time_str: [cite: 109]
                try:
                    [cite_start]last_failed_datetime = datetime.fromisoformat(last_failed_time_str) [cite: 109]
                    [cite_start]if (current_time - last_failed_datetime).total_seconds() / 3600 > CONFIG['channel_retention']['url_retention_hours']: [cite: 109]
                        [cite_start]remove_url = True [cite: 109]
                        [cite_start]logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且超出保留时间 ({CONFIG['channel_retention']['url_retention_hours']}h)") [cite: 110]
                except ValueError:
                    [cite_start]logging.warning(f"无法解析 URL {url} 的最后失败时间戳: {last_failed_time_str}") [cite: 110]
            else:
                [cite_start]remove_url = True [cite: 110]
                [cite_start]logging.info(f"移除 URL '{url}'，因失败次数过多 ({fail_count}) 且无最后失败时间戳") [cite: 111]

        [cite_start]if not remove_url: [cite: 111]
            [cite_start]urls_to_keep.append(url) [cite: 111]
        else:
            [cite_start]removed_count += 1 [cite: 111]
            [cite_start]url_states.pop(url, None) [cite: 111]

    [cite_start]if removed_count > 0: [cite: 111]
        [cite_start]logging.warning(f"从 {urls_file_path_local} 清理 {removed_count} 个 URL") [cite: 112]
        [cite_start]write_array_to_txt_local(urls_file_path_local, urls_to_keep) [cite: 112]
    else:
        [cite_start]logging.warning("无需清理 urls.txt 中的 URL") [cite: 112]

# --- 分类和文件保存函数 ---
@performance_monitor
def categorize_channels(channels):
    [cite_start]"""根据频道名称关键字分类，并应用类别别名进行规范化 [cite: 112]
    参数:
        [cite_start]channels: 包含频道名称和 URL 的列表 [cite: 112]
    返回:
        [cite_start]元组 (分类后的频道字典, 未分类频道列表, 最终排序的分类列表) [cite: 113]
    """
    [cite_start]categorized_data = {category: [] for category in CONFIG.get('ordered_categories', [])} [cite: 113]
    [cite_start]uncategorized_data = [] [cite: 113]

    [cite_start]category_aliases = CONFIG.get('category_aliases', {}) [cite: 113]

    for name, url in channels:
        [cite_start]found_category = False [cite: 113]
        # [cite_start]按照 ordered_categories 的顺序尝试匹配 [cite: 113]
        [cite_start]for category in CONFIG.get('ordered_categories', []): [cite: 113]
            [cite_start]category_keywords = CONFIG['category_keywords'].get(category, []) [cite: 113]
            # [cite_start]检查频道名称是否包含任何一个关键字 [cite: 113]
            if any(keyword.lower() in name.lower() for keyword in category_keywords):
                # [cite_start]应用类别别名 [cite: 114]
                [cite_start]final_category = category_aliases.get(category, category) [cite: 114]
                
                # [cite_start]如果别名后的类别是新类别，确保其在 categorized_data 中存在 [cite: 114]
                if final_category not in categorized_data:
                    [cite_start]categorized_data[final_category] = [] [cite: 114]

                [cite_start]categorized_data[final_category].append((name, url)) [cite: 114]
                [cite_start]found_category = True [cite: 115]
                [cite_start]break # 找到匹配的类别后就停止，因为 ordered_categories 保证了优先级 [cite: 115]
        
        [cite_start]if not found_category: [cite: 115]
            [cite_start]uncategorized_data.append((name, url)) [cite: 115]
            
    # [cite_start]清理掉空的分类 [cite: 115]
    categorized_data_cleaned = {
        [cite_start]k: v for k, v in categorized_data.items() [cite: 115, 116] if v
    }
    
    # [cite_start]将别名后的类别也添加到 ordered_categories 中，以便后续写入文件时按顺序 [cite: 116]
    # [cite_start]确保所有使用的类别都在 ordered_categories 中 [cite: 116]
    [cite_start]all_final_categories = list(categorized_data_cleaned.keys()) [cite: 116]
    [cite_start]for alias_target in set(category_aliases.values()): [cite: 116]
        if alias_target not in all_final_categories:
            [cite_start]all_final_categories.append(alias_target) [cite: 116]
            
    # [cite_start]根据原始 ordered_categories 的顺序对最终的类别进行排序 [cite: 116]
    [cite_start]final_ordered_categories = [cat for cat in CONFIG.get('ordered_categories', []) if cat in all_final_categories] [cite: 116]
    # [cite_start]添加可能通过别名产生但不在原始 [cite: 117] [cite_start]ordered_categories 中的新类别 [cite: 117]
    for cat in sorted(all_final_categories):
        if cat not in final_ordered_categories:
            [cite_start]final_ordered_categories.append(cat) [cite: 117]

    [cite_start]return categorized_data_cleaned, uncategorized_data, final_ordered_categories [cite: 117]

@performance_monitor
def process_and_save_channels_by_category(all_channels, url_states, source_tracker):
    [cite_start]"""将频道分类并保存到对应文件 [cite: 117]
    参数:
        [cite_start]all_channels: 所有频道列表 [cite: 117]
        [cite_start]url_states: URL 状态字典 [cite: 118]
        [cite_start]source_tracker: 跟踪频道来源的字典 [cite: 118]
    """
    [cite_start]categorized_channels, uncategorized_channels, final_ordered_categories = categorize_channels(all_channels) [cite: 118]
    [cite_start]categorized_dir = CONFIG['output']['paths']['channels_dir'] [cite: 118]
    [cite_start]os.makedirs(categorized_dir, exist_ok=True) [cite: 118]

    [cite_start]for category in final_ordered_categories: [cite: 118]
        [cite_start]channels = categorized_channels.get(category) [cite: 118]
        [cite_start]if channels: [cite: 118]
            [cite_start]output_file = os.path.join(categorized_dir, f"{category}_iptv.txt") [cite: 118]
            [cite_start]logging.warning(f"处理分类: {category}，包含 {len(channels)} 个频道") [cite: 119]
            [cite_start]sorted_channels = sorted(channels, key=lambda x: x[0]) [cite: 119]
            [cite_start]channels_to_write = [(0, f"{name},{url}") for name, url in sorted_channels] [cite: 119]
            [cite_start]write_sorted_channels_to_file(output_file, channels_to_write) [cite: 119]
    
    [cite_start]output_uncategorized_file = CONFIG['output']['paths']['uncategorized_channels_file'] [cite: 119]
    [cite_start]logging.warning(f"处理未分类频道: {len(uncategorized_channels)} 个频道") [cite: 119]
    [cite_start]sorted_uncategorized = sorted(uncategorized_channels, key=lambda x: x[0]) [cite: 120]
    [cite_start]uncategorized_to_write = [(0, f"{name},{url}") for name, url in sorted_uncategorized] [cite: 120]
    [cite_start]write_sorted_channels_to_file(output_uncategorized_file, uncategorized_to_write) [cite: 120]
    [cite_start]logging.warning(f"未分类频道保存到: {output_uncategorized_file}") [cite: 120]

# --- 主逻辑 ---
@performance_monitor
def main():
    [cite_start]"""主函数，执行 IPTV 处理流程 [cite: 120]
    包含以下步骤：
    1. [cite_start]加载 URL 状态 [cite: 120]
    2. [cite_start]从 GitHub 自动发现新 URL [cite: 120]
    3. [cite_start]清理无效 URL (注意: 基于网络可达性的清理已移除) [cite: 120]
    4. [cite_start]加载 URL 列表 [cite: 120, 121]
    5. [cite_start]多线程提取频道 [cite: 121]
    6. [cite_start]过滤和修改频道 [cite: 121]
    7. [cite_start]分类并保存频道 [cite: 121]
    8. [cite_start]合并频道文件 [cite: 121]
    9. [cite_start]保存 URL 状态 [cite: 121]
    10. [cite_start]清理临时文件 [cite: 121]
    """
    [cite_start]logging.warning("开始执行 IPTV 处理脚本") [cite: 120]
    [cite_start]total_start_time = time.time() [cite: 120]

    # [cite_start]步骤 1：加载 URL 状态 [cite: 120]
    [cite_start]url_states = load_url_states_local() [cite: 120]
    [cite_start]logging.warning(f"加载 {len(url_states)} 个 URL 状态") [cite: 120]

    # [cite_start]步骤 2：从 GitHub 自动发现新 URL [cite: 120]
    [cite_start]auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN) [cite: 120]

    # [cite_start]步骤 3：清理无效 URL (注意: 基于网络可达性的清理已移除，仅保留了基于上次检查失败时间的清理逻辑，但因检查功能移除而不再生效) [cite: 120]
    [cite_start]cleanup_urls_local(URLS_PATH, url_states) [cite: 120]

    # [cite_start]步骤 4：加载 URL 列表 [cite: 121]
    [cite_start]urls = read_txt_to_array_local(URLS_PATH) [cite: 121]
    if not urls:
        [cite_start]logging.error("未在 urls.txt 中找到 URL，退出") [cite: 121]
        [cite_start]exit(1) [cite: 121]
    [cite_start]logging.warning(f"从 '{URLS_PATH}' 加载 {len(urls)} 个 URL") [cite: 121]

    # [cite_start]步骤 5：多线程提取频道（限制最大 URL 数量以调试） [cite: 121]
    [cite_start]all_extracted_channels = [] [cite: 121]
    [cite_start]source_tracker = {} [cite: 121]
    [cite_start]logging.warning(f"开始从 {len(urls)} 个 URL 提取频道") [cite: 121]
    [cite_start]max_urls = 100  # 临时限制为 100 个 URL 以调试 [cite: 121]
    [cite_start]urls_to_process = urls[:max_urls] [cite: 122]
    [cite_start]logging.warning(f"调试模式：仅处理前 {len(urls_to_process)} 个 URL") [cite: 122]
    [cite_start]with ThreadPoolExecutor(max_workers=min(CONFIG['network']['url_fetch_workers'], [cite: 122] 10)) as executor:
        [cite_start]futures = {executor.submit(extract_channels_from_url, url, url_states, source_tracker): url for url in urls_to_process} [cite: 122]
        for i, future in enumerate(as_completed(futures)):
            [cite_start]url = futures[future] [cite: 122]
            [cite_start]if (i + 1) % CONFIG['performance_monitor']['log_interval'] == 0: [cite: 122]
                [cite_start]logging.warning(f"已处理 {i + 1}/{len(urls_to_process)} 个 URL") [cite: 122]
            try:
                [cite_start]channels = future.result() [cite: 123]
                [cite_start]if channels: [cite: 123]
                    [cite_start]all_extracted_channels.extend(channels) [cite: 123]
                [cite_start]logging.info(f"完成 URL {url} 的频道提取，获取 {len(channels)} 个频道") [cite: 123]
            except Exception as exc:
                [cite_start]logging.error(f"URL {url} 提取异常: {exc}") [cite: 124]
    [cite_start]logging.warning(f"完成频道提取，过滤前总计提取 {len(all_extracted_channels)} 个频道") [cite: 124]

    # [cite_start]步骤 6：过滤和修改频道 [cite: 124]
    [cite_start]filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels) [cite: 124]
    [cite_start]logging.warning(f"过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道") [cite: 125]

    # [cite_start]步骤 7：分类并保存频道 [cite: 125]
    [cite_start]process_and_save_channels_by_category(filtered_and_modified_channels, url_states, source_tracker) [cite: 125]

    # [cite_start]步骤 8：合并频道文件 [cite: 125]
    [cite_start]merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states) [cite: 125]

    # [cite_start]步骤 9：保存 URL 状态 [cite: 125]
    [cite_start]save_url_states_local(url_states) [cite: 125]
    [cite_start]logging.warning("最终频道检查状态已保存") [cite: 125]

    # [cite_start]步骤 10：清理临时文件（保留未分类文件） [cite: 125]
    try:
        [cite_start]temp_files = ['iptv.txt', 'iptv_speed.txt'] [cite: 125]
        [cite_start]for temp_file in temp_files: [cite: 125]
            [cite_start]if os.path.exists(temp_file): [cite: 125]
                [cite_start]os.remove(temp_file) [cite: 126]
                [cite_start]logging.info(f"移除临时文件 '{temp_file}'") [cite: 126]
        [cite_start]temp_dir = CONFIG['output']['paths']['channels_dir'] [cite: 126]
        [cite_start]if os.path.exists(temp_dir): [cite: 126]
            [cite_start]for f_name in os.listdir(temp_dir): [cite: 126]
                [cite_start]if f_name.endswith('_iptv.txt'): [cite: 126]
                    [cite_start]os.remove(os.path.join(temp_dir, f_name)) [cite: 126]
                    [cite_start]logging.info(f"移除临时频道文件 '{f_name}'") [cite: 126]
            [cite_start]if not os.listdir(temp_dir): [cite: 126]
                [cite_start]os.rmdir(temp_dir) [cite: 127]
                [cite_start]logging.info(f"移除空目录 '{temp_dir}'") [cite: 127]
        [cite_start]logging.warning(f"保留未分类文件 '{CONFIG['output']['paths']['uncategorized_channels_file']}'") [cite: 127]
    [cite_start]except Exception as e: [cite: 127]
        [cite_start]logging.error(f"清理临时文件失败: {e}") [cite: 127]

    [cite_start]total_elapsed_time = time.time() - total_start_time [cite: 127]
    [cite_start]logging.warning(f"IPTV 处理脚本完成，总耗时 {total_elapsed_time:.2f} 秒") [cite: 127]

if __name__ == "__main__":
    main()
