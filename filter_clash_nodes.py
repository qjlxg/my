import yaml
import sys
import os
import re

# --- 配置开关 ---
# 将此设置为 True 启用区域过滤（排除国内节点和保留特定国际节点），
# 设置为 False 关闭区域过滤，所有通过其他校验的节点都会被保留。
ENABLE_REGION_FILTERING = False 
# --- 

try:
    input_file = 'clash_config.yaml'
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    filtered_proxies = []
    # 用于跟踪已处理的代理名称，以便处理重复名称
    seen_proxy_names = {} 

    if 'proxies' in config and isinstance(config['proxies'], list):
        for i, proxy in enumerate(config['proxies']):
            # --- 确保代理是字典类型且包含 'type' 字段 ---
            if not isinstance(proxy, dict) or 'type' not in proxy:
                print(f"Warning: Proxy {i+1}: Skipping malformed proxy entry or entry without 'type' key: {proxy.get('name', 'Unnamed') if isinstance(proxy, dict) else str(proxy)[:50]}...", file=sys.stderr)
                continue

            proxy_type = proxy['type']
            original_proxy_name = proxy.get('name', f"Unnamed Proxy {i+1}")
            proxy_name = original_proxy_name # 初始化为原始名称

            is_valid_node = True
            missing_fields = []

            # --- 增强的 VMess 错误排除：针对 unsupported security type 和 cipher missing ---
            if proxy_type == 'vmess':
                valid_vmess_ciphers = [
                    'auto', 'none', 'aes-128-gcm', 'chacha20-poly1305',
                    'chacha20-ietf-poly1305',
                    'aes-256-gcm'
                ]
                
                vmess_cipher = proxy.get('cipher')

                if vmess_cipher is None:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy because 'cipher' field is missing. This often causes 'key 'cipher' missing' error.", file=sys.stderr)
                    is_valid_node = False
                elif not isinstance(vmess_cipher, str) or vmess_cipher.strip() == '':
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to invalid or empty 'cipher' field (received: '{vmess_cipher}'). This incessantly causes 'unsupported security type' error.", file=sys.stderr)
                    is_valid_node = False
                elif vmess_cipher.lower() not in valid_vmess_ciphers:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VMess proxy due to unsupported 'cipher' type ('{vmess_cipher}'). This often causes 'unsupported security type' error.", file=sys.stderr)
                    is_valid_node = False

            # --- 针对不同代理类型校验所需的关键字段是否存在 ---
            if proxy_type == 'vmess':
                required_fields = ['server', 'port', 'uuid', 'alterId']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'trojan':
                required_fields = ['server', 'port', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'ss':
                required_fields = ['server', 'port', 'cipher', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
                # 特殊处理：排除 cipher 为 'ss' 的 SS 节点
                if proxy.get('cipher') is None or (isinstance(proxy.get('cipher'), str) and proxy.get('cipher').lower() == 'ss'):
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SS proxy due to missing or unsupported 'cipher' method ('{proxy.get('cipher', 'missing') if proxy.get('cipher') is not None else 'missing'}').", file=sys.stderr)
                    is_valid_node = False

            elif proxy_type == 'vless':
                required_fields = ['server', 'port', 'uuid']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
                vless_security = proxy.get('security')
                if vless_security is not None:
                    if not isinstance(vless_security, str) or \
                       (isinstance(vless_security, str) and vless_security.strip() == '') or \
                       (vless_security.lower() not in ['tls', 'none']):
                        print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping VLESS proxy due to unsupported or empty 'security' field ('{vless_security}').", file=sys.stderr)
                        is_valid_node = False
            elif proxy_type == 'hysteria2':
                required_fields = ['server', 'port', 'password']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
            elif proxy_type == 'ssr':
                required_fields = ['server', 'port', 'cipher', 'password', 'protocol', 'obfs']
                for field in required_fields:
                    if field not in proxy:
                        missing_fields.append(field)
                if missing_fields:
                    is_valid_node = False
                if proxy.get('cipher') is None:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy due to missing 'cipher' field.", file=sys.stderr)
                    is_valid_node = False
                # --- 新增：SSR obfs-param 校验 ---
                # 如果 obfs 字段存在，则 obfs-param 不能为空或缺失
                if 'obfs' in proxy and proxy['obfs'] is not None and proxy['obfs'].strip() != '':
                    if 'obfs-param' not in proxy or proxy['obfs-param'] is None or proxy['obfs-param'].strip() == '':
                        print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping SSR proxy because 'obfs' is specified but 'obfs-param' is missing or empty. This causes 'missing obfs password' or similar errors.", file=sys.stderr)
                        is_valid_node = False
                # --- SSR obfs-param 校验结束 ---
            else:
                # 警告并跳过不支持的代理类型，但不会导致脚本退出
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping unsupported proxy type '{proxy_type}'.", file=sys.stderr)
                continue


            # 如果节点在上述校验中被标记为无效，则跳过
            if not is_valid_node:
                if missing_fields:
                    print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy due to missing required fields: {', '.join(missing_fields)}.", file=sys.stderr)
                continue

            # 确保 'server' 或 'host' 字段存在以获取服务器地址，这是后续判断的基础
            server_address = proxy.get('server')
            if not server_address:
                server_address = proxy.get('host')
            
            if not server_address:
                print(f"Warning: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it has no 'server' or 'host' key (secondary check).", file=sys.stderr)
                continue

            # --- 区域过滤逻辑 (根据 ENABLE_REGION_FILTERING 开关控制) ---
            if ENABLE_REGION_FILTERING:
                # 定义要排除的国内地区关键词（中文和拼音），以及常见的国内云服务商
                keywords_to_exclude = [
                    'cn', 'china', '中国', '大陆', 'tencent', 'aliyun', '华为云', '移动', '联通', '电信', # 省份
                    '北京', '上海', '广东', '江苏', '浙江', '四川', '重庆', '湖北', '湖南', '福建', '山东',
                    '河南', '河北', '山西', '陕西', '辽宁', '吉林', '黑龙江', '安徽', '江西', '广西', '云南',
                    '贵州', '甘肃', '青海', '宁夏', '新疆', '西藏', '内蒙古', '天津', '海南', 'hk', 'tw', 'mo'
                ]
                
                is_domestic_node = False
                # 检查服务器地址是否包含排除关键词
                for keyword in keywords_to_exclude:
                    if keyword.lower() in server_address.lower():
                        is_domestic_node = True
                        break
                
                # 如果服务器地址未匹配到，则检查节点名称是否包含排除关键词
                if not is_domestic_node:
                    for keyword in keywords_to_exclude:
                        if keyword.lower() in proxy_name.lower():
                            is_domestic_node = True
                            break

                if is_domestic_node:
                    print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it appears to be a domestic Chinese node or a region often considered domestic by VPN users (HK/TW/MO for some policies). Server/Host: {server_address}", file=sys.stderr)
                    continue # 跳过此代理


                # 定义靠近中国的地区关键词，用于匹配服务器地址或节点名称 (这些是您希望保留的国际节点)
                keywords_to_keep_near_china = ['sg', 'jp', 'kr', 'ru'] 

                matched_region_to_keep = False
                # 检查服务器地址是否包含保留关键词
                for keyword in keywords_to_keep_near_china:
                    if keyword.lower() in server_address.lower():
                        matched_region_to_keep = True
                        break
                
                # 如果服务器地址未匹配到，则检查节点名称是否包含保留关键词
                if not matched_region_to_keep:
                    for keyword in keywords_to_keep_near_china:
                        if keyword.lower() in proxy_name.lower():
                            matched_region_to_keep = True
                            break

                # 如果开启了过滤，但节点不属于要保留的区域，则跳过
                if not matched_region_to_keep: 
                    print(f"Info: Proxy {i+1} ('{proxy_name}'): Skipping proxy as it does not match close-to-China international regions. Server/Host: {server_address}", file=sys.stderr)
                    continue # 跳过此代理
            # --- 区域过滤逻辑结束 ---

            # --- 处理重复名称：确保最终输出的节点名称唯一 ---
            # 这里使用原始名称来检查，然后更新字典中的实际名称
            temp_name_check = original_proxy_name
            if temp_name_check in seen_proxy_names:
                count = seen_proxy_names[temp_name_check]
                new_name = f"{temp_name_check}_duplicate_{count}"
                print(f"Warning: Proxy {i+1}: Node name '{temp_name_check}' is a duplicate. Renaming to '{new_name}'.", file=sys.stderr)
                proxy['name'] = new_name
                seen_proxy_names[temp_name_check] += 1 # 增加原始名称的计数
                seen_proxy_names[new_name] = 1 # 将新名称也标记为已使用，以防万一
                proxy_name = new_name # 更新当前处理的 proxy_name 变量
            else:
                seen_proxy_names[temp_name_check] = 1
            
            # --- 类型转换和最终添加（无论区域过滤是否开启，这些都执行） ---
            # 处理 'tls' 字段的类型转换 (字符串 "true" / "false" 到布尔值)
            if 'tls' in proxy:
                tls_value = proxy['tls']
                if isinstance(tls_value, str):
                    proxy['tls'] = tls_value.lower() == 'true'
                elif not isinstance(tls_value, bool):
                    # 如果不是字符串也不是布尔值，则设为 False，避免 YAML 导出问题
                    proxy['tls'] = False
            
            filtered_proxies.append(proxy) # 如果通过所有检查（包括可选的区域过滤和名称唯一性检查），则添加到过滤列表中

    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config. Output will be an empty proxies list.", file=sys.stderr)

    # --- 输出过滤后的配置到文件 ---
    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

# --- 异常处理 ---
except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
