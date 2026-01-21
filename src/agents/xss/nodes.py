import json
import httpx
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.utils.auditor import auditor
from src.core.llm.service import create_audited_llm
from src.agents.xss.state import XSSState
from loguru import logger
from src.agents.base.nodes import BaseVulnNodes

from src.core.prompts.xss import XSS_GENERATOR_PROMPT, XSS_ANALYZER_PROMPT

class XSSNodes(BaseVulnNodes):
    def __init__(self):
        super().__init__(retry_key="xss_retry_count")
        # 从文件加载静态 Payloads
        self.STATIC_PAYLOADS = self._load_static_payloads("src/core/payloads/xss.txt")

    async def strategist_node(self, state: XSSState) -> dict:
        """调用通用引擎生成 XSS Payload"""
        
        # 策略 1: 如果是首次执行 (retry_count == 0 且无 feedback)，使用静态 Payload
        if state.get(self.retry_key, 0) == 0 and not state.get("analysis_feedback"):
            logger.info("XSS 首次执行，使用静态高频 Payloads 进行探测")
            
            points = state.get("potential_points", [])
            if not points:
                logger.warning("没有发现潜在注入点，跳过静态探测")
                return {"planned_data": None}

            # 1. 构造带占位符的原始数据包 (安全替换)
            fuzzed_request = self._build_fuzzed_request(state, points)
            
            static_cases = []
            
            # 简单的启发式筛选：为避免请求爆炸，只对前 3 个参数进行测试
            target_points = points[:3] if len(points) > 3 else points

            # 2. 生成测试用例
            for point in target_points:
                placeholder = point["placeholder"]
                for payload in self.STATIC_PAYLOADS:
                    static_cases.append({
                        "parameter": placeholder,
                        "payload": payload
                    })
            
            if static_cases:
                logger.info(f"生成静态 XSS 测试用例: {len(static_cases)} 个")
                structured_data = {
                    "request": fuzzed_request,
                    "test_cases": static_cases
                }
                return {"planned_data": structured_data}

        # 策略 2: 如果静态测试失败或有反馈，调用 LLM 进行针对性生成
        return await self._generic_strategist_node(state, XSS_GENERATOR_PROMPT, "XSS")

    async def analyzer_node(self, state: XSSState) -> dict:
        """XSS 专用分析器：结合字符串匹配与 LLM 深度分析"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", XSS_ANALYZER_PROMPT),
            ("user", "原始响应上下文: {results}")
        ])
        
        # 准备汇总给 LLM
        results_summary = []
        for res in state["test_results"]:
            reflected = res["payload"] in res.get("response", "")
            results_summary.append({
                "parameter": res.get("parameter"),
                "payload": res.get("payload"),
                "reflected_directly": reflected,
                "response_slice": res.get("response", "")[:500]
            })

        return await self._generic_analyzer_node(
            state=state,
            prompt=prompt,
            results_summary=results_summary,
            vuln_type="XSS",
            findings_type="Reflected XSS",
            agent_name="XSS_Analyzer"
        )

