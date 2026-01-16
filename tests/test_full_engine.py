import asyncio
import uuid
import json
import os
import sys
from pathlib import Path

# 将项目根目录添加到 sys.path
root_path = Path(__file__).parent.parent
sys.path.append(str(root_path))

from loguru import logger
from src.config.settings import settings
from src.agents.sqli.graph import sqli_graph
from src.agents.xss.graph import xss_graph
from src.agents.manager.state import AgentState

async def test_sqli_post_batch():
    logger.info("=== 开始测试: SQLi 批量 POST 探测 (异步) ===")
    
    mock_state: AgentState = {
        "request_id": f"test-sqli-{uuid.uuid4().hex[:6]}",
        "target_url": "http://example.com/api/login",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"username": "admin", "password": "123", "token": "abc"}),
        "tasks": ["sqli"],
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "sqli_retry_count": 0,
        "findings": []
    }

    # 执行 SQLi 子图 (异步 invoke)
    final_state = await sqli_graph.ainvoke(mock_state)
    
    logger.success(f"SQLi 测试完成！")
    logger.info(f"识别到的注入点: {final_state.get('potential_points')}")
    logger.info(f"是否发现漏洞: {final_state.get('is_vulnerable')}")
    logger.info(f"汇总发现数量: {len(final_state.get('findings', []))}")
    if final_state.get("is_vulnerable"):
        logger.warning(f"PoC: {final_state.get('proof_of_concept')}")

async def test_xss_get_batch():
    logger.info("=== 开始测试: XSS 批量 GET 探测 (异步) ===")
    
    mock_state: AgentState = {
        "request_id": f"test-xss-{uuid.uuid4().hex[:6]}",
        "target_url": "http://example.com/search?q=apple&category=fruit&page=1",
        "method": "GET",
        "headers": {},
        "body": None,
        "tasks": ["xss"],
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "xss_retry_count": 0,
        "findings": []
    }

    # 执行 XSS 子图 (异步 invoke)
    final_state = await xss_graph.ainvoke(mock_state)
    
    logger.success(f"XSS 测试完成！")
    logger.info(f"是否发现漏洞: {final_state.get('is_vulnerable')}")
    logger.info(f"汇总发现数量: {len(final_state.get('findings', []))}")
    if final_state.get("is_vulnerable"):
        logger.warning(f"PoC: {final_state.get('proof_of_concept')}")

async def main():
    # 如果设置了环境变量 SCAN_PROXY，则更新配置
    proxy = os.getenv("SCAN_PROXY")
    if proxy:
        logger.info(f"检测到代理配置: {proxy}")
        settings.SCAN_PROXY = proxy
    
    # 运行测试
    try:
        await test_sqli_post_batch()
        print("\n" + "="*50 + "\n")
        await test_xss_get_batch()
    except Exception as e:
        logger.error(f"测试过程中出现错误: {e}")

if __name__ == "__main__":
    asyncio.run(main())
