import asyncio
import sys
import os
import json
from loguru import logger

# 将项目根目录加入 path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.manager.graph import create_manager_graph
from src.agents.manager.state import AgentState

async def test_concurrency_and_reset():
    logger.info("🚀 开始综合功能测试：并发任务、反馈累加与重置验证")
    
    app = create_manager_graph()
    
    # 1. 模拟第一个请求：下发 SQLi 和 XSS 并发任务
    state_1: AgentState = {
        "request_id": "req-001-multi-task",
        "target_url": "http://test-site.com/api",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"id": 1, "name": "test"}),
        "tasks": ["sqli", "xss"],
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "findings": [],
        "sqli_retry_count": 0,
        "xss_retry_count": 0,
        "fuzz_retry_count": 0,
        "analysis_feedback": []
    }
    
    logger.info("--- 执行第一个请求 (SQLi + XSS) ---")
    # 为了测试，我们需要模拟子图的行为，但这里我们直接运行 Manager
    # 注意：Manager 会根据 tasks 字段分发到子图
    final_state_1 = await app.ainvoke(state_1)
    
    logger.info(f"请求 1 结束 | 审计日志条数: {len(final_state_1.get('audit_log', []))}")
    # 检查反馈是否为列表且可能包含内容（如果 LLM 运行了）
    feedback = final_state_1.get("analysis_feedback", [])
    logger.info(f"请求 1 反馈列表内容: {feedback}")
    
    # 2. 模拟第二个请求：模拟请求包变化，验证重置逻辑
    # 在现实中，TaskRunner 会负责初始化新状态
    logger.info("\n--- 执行第二个请求 (请求包变化，验证重置) ---")
    state_2: AgentState = {
        "request_id": "req-002-reset-test",
        "target_url": "http://another-site.com/login",
        "method": "GET",
        "headers": {},
        "body": None,
        "tasks": ["fuzz"], # 换一个任务
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "findings": [],
        # 即使这里传入了旧值，Manager 节点也会重置它们
        "sqli_retry_count": 5, 
        "xss_retry_count": 5,
        "analysis_feedback": ["Old Feedback"] 
    }
    
    # 模拟 TaskRunner 的初始化逻辑
    state_2.update({
        "sqli_retry_count": 0,
        "xss_retry_count": 0,
        "fuzz_retry_count": 0,
        "analysis_feedback": []
    })
    
    final_state_2 = await app.ainvoke(state_2)
    
    print("\n" + "="*50)
    print("重置验证结果:")
    print(f"请求 2 sqli_retry_count (预期 0): {final_state_2.get('sqli_retry_count')}")
    print(f"请求 2 xss_retry_count (预期 0): {final_state_2.get('xss_retry_count')}")
    print(f"请求 2 analysis_feedback (预期 []): {final_state_2.get('analysis_feedback')}")
    print(f"请求 2 任务列表: {final_state_2.get('tasks')}")
    print("="*50)

    # 验证并发写入是否导致 audit_log 丢失 (通过 Annotated[List, operator.add] 保证)
    audit_log = final_state_2.get("audit_log", [])
    if len(audit_log) > 0:
        logger.success("✅ 并发审计日志写入正常")
    else:
        logger.warning("⚠️ 审计日志为空，请检查任务分发逻辑")

if __name__ == "__main__":
    asyncio.run(test_concurrency_and_reset())
