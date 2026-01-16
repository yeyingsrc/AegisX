import asyncio
import sys
import os

# 将项目根目录加入 path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.fuzz.graph import create_fuzz_graph
from src.utils.redis_helper import redis_helper
from src.config.settings import settings

# 模拟 Redis 中的历史参数
def setup_redis_data(host: str):
    print(f"Setting up history params for {host}...")
    redis_helper.client.sadd(f"webagent:host:{host}:params", "admin", "debug", "internal_id", "token")

async def test_fuzz_workflow():
    # 1. 准备测试数据
    target_host = "httpbin.org"
    setup_redis_data(target_host)
    
    initial_state = {
        "target_url": f"https://{target_host}/",
        "method": "POST",
        "headers": {"Host": target_host, "User-Agent": "TestAgent"},
        "body": "q=test",
        "fuzz_retry_count": 0,
        "potential_points": [],
        "history_params": [],
        "test_results": [],
        "findings": [],
        "analysis_feedback": "",
        # AgentState 必需字段
        "request_id": "test-fuzz-001",
        "response_headers": {},
        "response_body": "",
        "tasks": ["fuzz"],
        "messages": [],
        "audit_log": []
    }

    # 2. 初始化图
    app = create_fuzz_graph()
    
    # 3. 运行图
    print("\nStarting Fuzz Workflow...")
    final_state = await app.ainvoke(initial_state)
    
    # 4. 验证结果
    print("\nWorkflow Finished.")
    print(f"Findings: {len(final_state.get('findings', []))}")
    print(f"Test Results: {len(final_state.get('test_results', []))}")
    
    # 验证是否利用了历史参数 (检查 payload 中是否包含 admin/debug 等)
    history_param_used = False
    for res in final_state.get("test_results", []):
        payload = res.get("payload", "")
        print(f"Payload: {payload}")
        if "admin" in payload or "debug" in payload:
            history_param_used = True
            
    if history_param_used:
        print("SUCCESS: History params were injected!")
    else:
        print("WARNING: No history params found in payloads (LLM might have chosen other strategies).")

if __name__ == "__main__":
    asyncio.run(test_fuzz_workflow())
