import json
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.utils.auditor import auditor
from src.core.llm.service import create_audited_llm
from src.agents.fuzz.state import FuzzState
from src.core.prompts.fuzz import FUZZ_GENERATOR_PROMPT, FUZZ_ANALYZER_PROMPT
from src.utils.redis_helper import redis_helper
from loguru import logger

from src.agents.base.nodes import BaseVulnNodes

class FuzzNodes(BaseVulnNodes):
    def __init__(self):
        super().__init__(retry_key="fuzz_retry_count")
    
    async def analyze_points_node(self, state: FuzzState) -> dict:
        """识别注入点并初始化状态"""
        # 调用基类的通用识别逻辑
        base_result = self.analyze_injection_points(state)
        
        # 可以在这里添加 Fuzz 特有的逻辑，比如确保 potential_points 不为空
        if not base_result.get("potential_points"):
             # 如果没有显式参数，Fuzz 仍然可以尝试 URL 路径或 Header (未来扩展)
             pass
             
        return base_result

    async def strategist_node(self, state: FuzzState) -> dict:
        """Fuzz 策略生成器：结合历史参数进行变异"""
        
        # 1. 获取 Host 历史参数
        try:
            url = state.get("target_url", "")
            host = ""
            if "://" in url:
                host = url.split("/")[2]
            elif "headers" in state and "Host" in state["headers"]:
                host = state["headers"]["Host"]
                
            history_params = []
            if host:
                history_params = redis_helper.get_host_params(host)
        except Exception as e:
            logger.error(f"Failed to fetch history params: {e}")
            history_params = []

        # 2. 注入历史参数到 Prompt
        history_params_str = ", ".join(history_params) if history_params else "None"
        # 确保 history_params 是安全的字符串，避免注入干扰 Prompt 结构
        history_params_str = history_params_str.replace("{", "{{").replace("}", "}}")
        
        final_prompt = FUZZ_GENERATOR_PROMPT.replace("{history_params}", history_params_str)
        
        
        return await self._generic_strategist_node(state, final_prompt, "Fuzz")

    async def analyzer_node(self, state: FuzzState) -> dict:
        """Fuzz 结果分析器"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", FUZZ_ANALYZER_PROMPT),
            ("user", "原始响应片段: {orig}\n测试结果: {results}")
        ])
        
        results_summary = []
        for r in state["test_results"]:
            summary_item = {
                "parameter": r.get("parameter"),
                "payload": r.get("payload"),
                "status": r.get("status"),
                "elapsed": r.get("elapsed"),
                "len_diff": r.get("len_diff"),
                "similarity": r.get("similarity")
            }
            # Fuzz 关注异常变化，若完全一致则无需展示响应
            if r.get("similarity", 1.0) < 0.99:
                summary_item["response_slice"] = r.get("response", "")[:500]
            
            results_summary.append(summary_item)

        return await self._generic_analyzer_node(
            state=state,
            prompt=prompt,
            results_summary=results_summary,
            vuln_type="Fuzz",
            findings_type="Anomaly/Vulnerability",
            agent_name="Fuzz_Analyzer"
        )

    def should_retry(self, state: FuzzState) -> str:
        """根据分析结果决定下一步"""
        decision = state.get("next_step", "give_up")
        retry_count = state.get("fuzz_retry_count", 0)
        
        if decision == "found":
            return "end"
        
        if decision == "retry" and retry_count < settings.SCAN_MAX_RETRIES:
            logger.info(f"Fuzz 决定重试 ({retry_count}/{settings.SCAN_MAX_RETRIES})")
            return "retry"
        
        return "end"
