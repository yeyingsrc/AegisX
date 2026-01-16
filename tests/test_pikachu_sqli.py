import sys
import os
import asyncio
import json
from pathlib import Path

# Add project root to sys.path
root_path = Path(__file__).parent.parent
sys.path.append(str(root_path))

from src.agents.sqli.graph import sqli_graph
from src.agents.manager.graph import graph
from loguru import logger

async def test_pikachu_packet():
    # 构造目标 URL，清理参数中的空格
    # 原始请求: GET /pikachu-master/vul/sqli/sqli_str.php? name = 24 & submit = %25E6%259F%25A5%25E8%25AF%25A2
    target_url = "http://127.0.0.1/pikachu-master/vul/sqli/sqli_str.php?name=24&submit=%E6%9F%A5%E8%AF%A2"
    
    headers = {
        "Host": "127.0.0.1",
        "sec-ch-ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "Sec-Fetch-Site": "same-origin",
        "Referer": "http://127.0.0.1/pikachu-master/vul/sqli/sqli_str.php",
        "Accept-Language": "zh-CN,zh;q=0.9,th;q=0.8",
        "sec-ch-ua-platform": '"Windows"',
        "Upgrade-Insecure-Requests": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-User": "?1",
        "Cookie": "PHPSESSID=3a23pd0a0b3ab33478cov8sfvu",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Accept-Encoding": "gzip, deflate, br, zstd"
    }

    state = {
        "request_id": "pikachu-test-001",
        "target_url": target_url,
        "method": "GET",
        "headers": headers,
        "body": None,
        "tasks": None,
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "findings": []
    }

    logger.info(f"🚀 开始测试 Pikachu SQLi 靶场: {target_url}")
    try:
        final_state = await graph.ainvoke(state)
        logger.info("测试执行完成")
        if final_state.get("findings"):
            logger.success(f"✅ 发现漏洞: {len(final_state['findings'])} 个")
            for finding in final_state['findings']:
                logger.success(f" - 参数: {finding.get('parameter')}")
                logger.success(f" - Payload: {finding.get('payload')}")
        else:
            logger.warning("⚠️ 未发现确认的 SQL 注入漏洞")
            
    except Exception as e:
        logger.error(f"❌ 测试出错 (可能是因为无法连接到 127.0.0.1): {e}")
        logger.info("提示: 请确保 Pikachu 靶场正在本地 127.0.0.1 运行，或者修改 target_url 为正确的 IP 地址。")

if __name__ == "__main__":
    asyncio.run(test_pikachu_packet())
