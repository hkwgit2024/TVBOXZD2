import aiohttp
import asyncio
import os
import re
import base64
import yaml
import json
import time
from urllib.parse import quote
from datetime import datetime, timezone

# --- 配置 ---
SEARCH_API_URL = "https://api.github.com/search/code"

# 从环境变量获取 GitHub 个人访问令牌
GITHUB_TOKEN = os.getenv("BOT")

# 扩展的搜索词，用于更广泛地覆盖内容
search_terms = [
    "v2ray  vmess",
    "proxies type:",
    "server: port:",
    "vless://", "vmess://", "trojan://", "ss://", "hysteria2://",
    "filename:*.yaml", "filename:*.yml",
    "proxy:", "nodes:", "servers:"
]

# 文件路径，用于输出结果
output_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
debug_log_file = "data/search_debug.log"

# --- 初始化 ---
os.makedirs("data", exist_ok=True)
debug_logs = [] # 存储调试日志消息

# --- 全局头信息，用于 GitHub API 请求 ---
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("Warning：BOT 环境变量未找到。使用未经身份验证的请求（较低速率限制）。")

# --- 新的锁定，用于安全地并发写入无效 URL 文件 ---
invalid_urls_write_lock = asyncio.Lock()

# --- 工具函数 ---

async def load_known_invalid_urls() -> set:
    known_invalid_urls = set()
    if os.path.exists(invalid_urls_file):
        with open(invalid_urls_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        max_invalid_urls_to_load = 1000 # 限制以防止过多的内存使用
        for line in lines[-max_invalid_urls_to_load:]:
            url_part = line.strip().split("|")
            if url_part:
                known_invalid_urls.add(url_part)
        debug_logs.append(f"已加载 {len(known_invalid_urls)} 个已知无效 URL。")
    return known_invalid_urls

async def check_rate_limit(session：aiohttp.ClientSession) -> int:
    try：
        async with session.get("https：//api.github.com/rate_limit", headers=headers) as response：
            response.raise_for_status()
            rate_limit = await response.json()
            remaining = rate_limit['rate']['remaining']
            reset_time = datetime.fromtimestamp(rate_limit['rate']['reset'], tz=timezone.utc)
            debug_logs.append(f"GitHub API 速率限制：剩余 {remaining} 次，恢复时间 {reset_time}。")
            return remaining
    except Exception e：
        debug_logs.append(f"检查速率限制失败：{e}")
        return 0

# --- 正则表达式模式 ---
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>"\'`]+', re.MULTILINE | re.IGNORECASE)
base64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?:[A-Za-z0-9+/]{16,})', re.MULTILINE)

irrelevant_extensions={'.png','.jpg','.jpeg','.gif','.bmp','.ico',
                       '.md','.markdown','.rst','.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
                       '.zip','.tar','.gz','.rar','.7z','.exe','.dll','.bin','.so','.lib',
                       '.log','.gitignore','.editorconfig','.gitattributes','.iml',
                       '.svg','.xml','.html','.htm','.css','.js','.jsx','.ts','.tsx','.py','.java','.c','.cpp','.h','.hpp','.php','.go','.rs','.swift','.kt','.sh','.bash','.ps1','.bat','.cmd','.rb','.pl'}

async def verify_content(session：aiohttp.ClientSession, url：str, known_invalid_urls：set) -> bool：
    if url in known_invalid_urls：
        debug_logs.append(f"跳过已知无效 URL：{url}")
        return False

    file_extension=os.path.splitext(url)[1].lower()
    if file_extension in irrelevant_extensions and file_extension!='.txt'：
        debug_logs.append(f"跳过无关的文件扩展名：{url}({file_extension})")
        await log_invalid_url(url,"无关文件类型")
        return False

    raw_url=url.replace("github.com","raw.githubusercontent.com").replace("/blob/","/")
    try：
        async with session.get(raw_url, headers=headers, timeout=20) as response：
            response.raise_for_status()
            content=await response.text()
            content=content[:1000000]

            if protocol_pattern.search(content)：
                debug_logs.append(f"在 {url} 中发现明文协议")
                return True

            base64_matches=base64_pattern.findall(content)
            for b64_str in base64_matches：
                try：
                    decoded=base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                    if protocol_pattern.search(decoded)：
                        debug_logs.append(f"在 {url} 中发现 Base64 解码后的协议")
                        return True
                    try：
                        json_data=json.loads(decoded)
                        if isinstance(json_data，dict) and any(key in json_data for key in ['v','ps','add','port','id','proxies','outbounds']):
                            debug_logs.append(f"在 {url} 中发现 Base64 JSON 代理配置")
                            return True
                    except json.JSONDecodeError：
                        pass

                except (base64.binascii.Error，UnicodeDecodeError):
                    continue

            if file_extension in {'.yaml','.yml','.conf','.json'} or not file_extension：
                try：
                    yaml_data=yaml.safe_load(content)
                    if isinstance(yaml_data，dict):
                        for key in ['proxies','proxy','nodes','servers','outbounds']:
                            if key in yaml_data：
                                proxies_config=yaml_data[key]
                                if (isinstance(proxies_config，list) and any(isinstance(p，dict) and any(k in p for k in ['server','port','type']) for p in proxies_config)) or \
                                   (isinstance(proxies_config，dict) and any(k in proxies_config for k in ['server','port','type']))：
                                    debug_logs.append(f"在 {url} 中发现 YAML/JSON 代理配置")
                                    return True

                except（yaml.YAMLError，json.JSONDecodeError）：
                    pass

            debug_logs.append(f“在 {url} 中没有找到目标协议或有效配置”)
            await log_invalid_url(url,"无代理配置找到")
            return False

    except aiohttp.ClientError e：
        debug_logs.append(f“获取 {url} 内容时发生网络/HTTP 错误：{e}")
        await log_invalid_url(url,f“获取内容失败：{type(e).__name__}")
        return False

    except asyncio.TimeoutError：
        debug_logs.append(f“获取 {url} 内容超时”)
        await log_invalid_url(url,"超时")
        return False

    except Exception e：
        debug_logs.append(f“验证 {url} 时发生未知错误：{e}")
        await log_invalid_url(url,f“验证错误：{type(e).__name__}")
        return False

async def log_invalid_url(url：str，reason：str)：
    async with invalid_urls_write_lock：
        try：
            with open(invalid_urls_file,"a+",encoding="utf-8") as f：
                f.seek(0)
                existing_lines=f.readlines()
                if not any(url in line for line in existing_lines):
                    f.write(f"{url}|{datetime.now(timezone.utc).isoformat()}|{reason}\n")
                    debug_logs.append(f“已记录无效 URL 到 {invalid_urls_file}：{url}（原因：{reason}）”)

        except Exception e：
            debug_logs.append(f“记录无效 URL {url} 到 {invalid_urls_file} 时发生错误：{e}")

async def search_and_process(session：aiohttp.ClientSession，term：str,max_pages：int,max_urls_to_find：int，known_invalid_urls：set，found_urls_set：set)：
    page=1
    current_search_count=0

    while page<=max_pages：
        remaining_requests=await check_rate_limit(session)
        if remaining_requests<20 and GITHUB_TOKEN:
            debug_logs.append(f“速率限制接近（剩余 {remaining_requests} 次）。等待恢复时间…”)
            reset_time_response=await session.get("https：//api.github.com/rate_limit", headers=headers)
            reset_data=await reset_time_response.json()
            reset_timestamp=reset_data['rate']['reset']
            wait_time=max(0,reset_timestamp-int(time.time()))+10
            debug_logs.append(f“等待 {wait_time} 秒前下一次请求…”)
            await asyncio.sleep(wait_time)
            remaining_requests=await check_rate_limit(session)
            if remaining_requests<20 and GITHUB_TOKEN:
                debug_logs.append(“速率限制未恢复或仍然过低。停止当前搜索项…”)
                break

        params={
            “q”：quote(term,safe=''),
            “per_page”：1000,
            “page”：page
        }
        debug_logs.append(f“搜索 {term}（页码 {page}）…”)

        try：
            async with session.get(SEARCH_API_URL，headers=headers,params=params,timeout=20) as response：
                response.raise_for_status()
                data=await response.json()

        except aiohttp.ClientError e：
            debug_logs.append(f“搜索 {term}（页码 {page}）失败（网络/HTTP 错误）：{e}")
            break

        except asyncio.TimeoutError：
            debug_logs.append(f“搜索 {term}（页码 {page}）超时…”)
            break

        except Exception e：
            debug_logs.append(f“搜索 {term}（页码 {page}）发生未知错误：{e}")
            break

        items=data.get(“items”，[])
        debug_logs.append(f“搜索 {term}（页码 {page}）找到 {len(items)} 个结果…”)

        if not items:
            break

        urls_to_verify=[]
        for item in items：
            html_url=item[“html_url”]
            if any(ext in html_url.lower() for ext in ['gfwlist','proxygfw','gfw.txt','gfw.pac']):
                debug_logs.append(f“跳过无关内容：{html_url}")
                await log_invalid_url(html_url,"无关内容（关键词匹配）")
                continue

            if html_url in known_invalid_urls or f"{html_url}" in "|".join(found_urls_set):
                debug_logs.append(f“跳过已处理或已知无效 URL：{html_url}")
                continue

            urls_to_verify.append(html_url)

        verification_tasks=[verify_content(session,url,known_invalid_urls) for url in urls_to_verify]
        verification_results=await asyncio.gather(*verification_tasks,return_exceptions=True)

        for i,result in enumerate(verification_results):
            original_url=urls_to_verify[i]
            if result is True:
                found_urls_set.add(f"{original_url}|{datetime.now(timezone.utc).isoformat()}")
                current_search_count+=1
                debug_logs.append(f“找到有效 URL:{original_url}（总数:{current_search_count}]”)

            elif isinstance(result ,Exception):
                debug_logs.append(f“验证 {original_url} 时发生异常：{result}")
                # log_invalid_url 已经在 verify_content 内部调用

            else:
                debug_logs.append(f“URL {original_url} 未通过验证…” )
                # log_invalid_url 已经在 verify_content 内部调用

            if current_search_count>=max_urls_to_find:
                debug_logs.append(f“达到目标数量 {max_urls_to_find} URL。停止搜索…” )
                return

        page+=1
        await asyncio.sleep(2 if GITHUB_TOKEN else 5 )

    debug_logs.append(f“搜索 {term} 完成所有页码或无更多结果…” )

# --- 主执行函数 ---

async def main（）：
    async with aiohttp.ClientSession（） as session：
         known_invalid_urls=await load_known_invalid_urls（）
         found_urls_set=set（）

         initial_rate_limit=await check_rate_limit（session）
         if initial_rate_limit==0 and GITHUB_TOKEN：
             debug_logs.append（"初始速率限制为0。无法进行搜索…"）
             return

         max_urls_to_find=200 
         max_pages_per_term=5 

         tasks=[]
         for term in search_terms：
             task=asyncio.create_task(search_and_process(session ,term ,max_pages_per_term ,max_urls_to_find ,known_invalid_urls ,found_urls_set))
             tasks.append(task)

         await asyncio.gather(*tasks ,return_exceptions=True )

         found_urls_list=sorted(list(found_urls_set))
         with open(output_file,"w",encoding="utf-8") as f：
             for url_entry in found_urls_list :
                 f.write(url_entry+"\n")
         debug_logs.append(f“找到 {len(found_urls_list)} 个URL，保存到 {output_file}")
         print(f“找到 {len(found_urls_list)} 个URL，保存到 {output_file}")

         with open(debug_log_file,"w",encoding="utf-8") as f :
              f.write("\n".join(debug_logs))
         print(f“调试日志保存到 {debug_log_file}")

if __name__== "__main__":
     asyncio.run(main()) 
