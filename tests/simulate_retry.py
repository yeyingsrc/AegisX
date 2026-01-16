import asyncio
import sys
import os
from unittest.mock import MagicMock, patch

# 将项目根目录加入 path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents.sqli.graph import create_sqli_graph
from src.agents.sqli.nodes import SQLiNodes
from loguru import logger

async def simulate_retry_3_times():
    logger.info("开始模拟 SQLi 重试 3 次的场景...")

    # 1. 准备初始状态
    initial_state = {
        "request_id": "sim-retry-123",
        "target_url": "http://example.com/api/user?id=1",
        "method": "GET",
        "headers": {},
        "body": None,
        "tasks": ["sqli"],
        "messages": [],
        "audit_log": [],
        "test_results": [],
        "sqli_retry_count": 0,  # 初始为 0
        "analysis_feedback": [],
        "findings": [],
        "potential_points": ["id"],
        "next_step": "none"
    }

    # 2. 模拟分析器节点：始终返回 retry
    async def mock_analyzer_node(state):
        current_retry = state.get("sqli_retry_count", 0)
        current_feedback = state.get("analysis_feedback", [])
        logger.warning(f"--- 模拟分析器: 当前重试次数 {current_retry}，决定再次重试 ---")
        new_feedback = current_feedback + [f"这是第 {current_retry + 1} 次重试的反馈"]
        return {
            "next_step": "retry",
            "sqli_retry_count": current_retry + 1,
            "analysis_feedback": new_feedback,
            "is_vulnerable": False
        }

    # 3. 模拟策略生成器和执行器（为了加快速度，不真正调用 LLM 和网络）
    async def mock_strategist_node(state):
        feedback_list = state.get("analysis_feedback", [])
        logger.info(f"--- 模拟生成器: 看到历史反馈数量: {len(feedback_list)} ---")
        if feedback_list:
            logger.debug(f"最新反馈内容: {feedback_list[-1]}")
        return {"test_results": [{"parameter": "id", "payload": "test'--", "status": 200}]}

    async def mock_executor_node(state):
        logger.info("--- 模拟执行器: 发送探测包 ---")
        return {"test_results": state.get("test_results", [])}

    # 4. 使用 patch 替换节点方法
    # 注意：create_sqli_graph 内部会实例化 SQLiNodes，我们需要 patch 掉它的方法
    with patch("src.agents.sqli.nodes.SQLiNodes.analyze_injection_points", side_effect=lambda x: {"potential_points": ["id"]}):
        with patch("src.agents.sqli.nodes.SQLiNodes.strategist_node", side_effect=mock_strategist_node):
            with patch("src.agents.sqli.nodes.SQLiNodes.executor_node", side_effect=mock_executor_node):
                with patch("src.agents.sqli.nodes.SQLiNodes.analyzer_node", side_effect=mock_analyzer_node):
                    
                    # 重新创建图以应用 mock
                    app = create_sqli_graph()
                    
                    # 5. 运行
                    final_state = await app.ainvoke(initial_state)

                    print("\n" + "="*50)
                    print("模拟运行结束")
                    print(f"最终 sqli_retry_count: {final_state.get('sqli_retry_count')}")
                    print(f"最终 next_step: {final_state.get('next_step')}")
                    print("="*50)

if __name__ == "__main__":
    asyncio.run(simulate_retry_3_times())
