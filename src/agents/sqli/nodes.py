import json
import httpx
import asyncio
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.utils.auditor import auditor
from src.core.llm.service import create_audited_llm
from src.agents.sqli.state import SQLiState
from loguru import logger
from src.agents.base.nodes import BaseVulnNodes

from src.core.prompts.sqli import SQLI_GENERATOR_PROMPT, SQLI_ANALYZER_PROMPT

class SQLiNodes(BaseVulnNodes):
    def __init__(self):
        super().__init__(retry_key="sqli_retry_count")
        # 从文件加载静态 Payloads
        self.STATIC_PAYLOADS = self._load_static_payloads("src/core/payloads/sqli.txt")

    async def strategist_node(self, state: SQLiState) -> dict:
        """调用通用引擎生成 SQLi Payload"""
        
        # 策略 1: 如果是首次执行 (retry_count == 0 且无 feedback)，使用静态 Payload
        if state.get(self.retry_key, 0) == 0 and not state.get("analysis_feedback"):
            logger.info("SQLi 首次执行，使用静态高频 Payloads (Wapiti Style) 进行探测")
            
            points = state.get("potential_points", [])
            if not points:
                logger.warning("没有发现潜在注入点，跳过静态探测")
                return {"planned_data": None}

            # 1. 构造带占位符的原始数据包 (安全替换)
            fuzzed_request = self._build_fuzzed_request(state, points)
            
            # 2. 生成测试用例
            static_cases = []
            target_points = points[:3] if len(points) > 3 else points

            for point in target_points:
                placeholder = point["placeholder"]
                for payload in self.STATIC_PAYLOADS:
                    static_cases.append({
                        "parameter": placeholder,
                        "payload": payload
                    })
            
            if static_cases:
                logger.info(f"生成静态测试用例: {len(static_cases)} 个")
                structured_data = {
                    "request": fuzzed_request,
                    "test_cases": static_cases
                }
                return {"planned_data": structured_data}

        # 策略 2: 如果静态测试失败或有反馈，调用 LLM 进行针对性生成
        return await self._generic_strategist_node(state, SQLI_GENERATOR_PROMPT, "SQLi")

    async def analyzer_node(self, state: SQLiState) -> dict:
        """SQLi 专用分析器"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", SQLI_ANALYZER_PROMPT),
            ("user", "原始响应片段: {orig}\n测试结果: {results}")
        ])
        
        # 限制发送给 LLM 的结果数量，避免上下文过长
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
            # 如果相似度过高（无变化），则省略 response_slice 以节省 Token
            if r.get("similarity", 1.0) < 0.99:
                summary_item["response_slice"] = r.get("response", "")[:300]
            
            results_summary.append(summary_item)

        return await self._generic_analyzer_node(
            state=state,
            prompt=prompt,
            results_summary=results_summary,
            vuln_type="SQLi",
            findings_type="SQL Injection",
            agent_name="SQLi_Analyzer"
        )

