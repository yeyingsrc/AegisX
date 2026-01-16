import json
import httpx
from typing import List, Dict, Optional, Any
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.core.llm.service import create_audited_llm
from src.core.engine.strategist import GenericStrategist
from src.core.engine.executor import GenericExecutor
from loguru import logger

class BaseVulnNodes:
    """
    漏洞扫描节点的基类，封装通用逻辑：
    1. 初始化引擎与 LLM
    2. 参数/注入点识别
    3. 异步探测执行
    4. 基础响应获取
    """
    def __init__(self, retry_key: str = "retry_count"):
        self.retry_key = retry_key
        self.strategist = GenericStrategist()
        self.executor = GenericExecutor(proxies=settings.SCAN_PROXY)
        self.audited_llm = create_audited_llm(
            model_name=settings.MODEL_NAME_WORKER,
            api_key=settings.OPENAI_API_KEY,
            api_base=settings.OPENAI_API_BASE,
            model_kwargs={"response_format": {"type": "json_object"}}
        )

    def analyze_injection_points(self, state: Dict[str, Any]) -> dict:
        """通用注入点识别：Query 参数 + Body 参数 + RESTful 路径参数"""
        points = []
        
        # 1. 提取 Query 参数
        if "?" in state["target_url"]:
            points.extend([p.split("=")[0] for p in state["target_url"].split("?")[1].split("&") if "=" in p])
        
        # 2. 提取 Body 参数 (如果存在)
        if state.get("body"):
            try:
                # 尝试解析 JSON body
                body_json = json.loads(state["body"])
                if isinstance(body_json, dict):
                    points.extend(list(body_json.keys()))
            except:
                # 尝试解析 form-urlencoded body
                points.extend([p.split("=")[0] for p in state["body"].split("&") if "=" in p])
        
        # 3. 启发式识别 RESTful 路径参数 (例如 /api/user/123)
        path_parts = state["target_url"].split("?")[0].split("/")
        for i, part in enumerate(path_parts):
            # 如果路径部分看起来像 ID (纯数字或 UUID 格式)
            if part.isdigit() or (len(part) > 30 and "-" in part):
                placeholder = "/".join(path_parts[:i] + ["{{PAYLOAD}}"] + path_parts[i+1:])
                points.append(placeholder)
                
        return {
            "potential_points": list(set(points)),
            self.retry_key: 0,
            "test_results": [],
            "analysis_feedback": []
        }

    async def executor_node(self, state: Dict[str, Any]) -> dict:
        """通用执行器节点"""
        results = await self.executor.execute_batch(
            target_url=state["target_url"],
            method=state["method"],
            test_cases=state.get("test_results", []),
            headers=state.get("headers"),
            original_body=state.get("body"),
            original_response=state.get("response_body")
        )
        return {"test_results": results}

    def _safe_json_parse(self, content: str, default_decision: str = "give_up") -> Dict[str, Any]:
        """通用的 LLM 响应 JSON 解析与错误处理"""
        try:
            return json.loads(content)
        except Exception as e:
            logger.error(f"JSON 解析失败: {e} | 内容: {content[:100]}")
            return {
                "is_vulnerable": False,
                "reasoning": f"JSON parse error: {str(e)}",
                "decision": default_decision
            }

    def _validate_decision(self, is_vulnerable: bool, decision: str, vuln_type: str) -> str:
        """通用决策校验逻辑 (防止 False + FOUND 矛盾)"""
        decision = decision.lower()
        if not is_vulnerable and decision == "found":
            logger.warning(f"{vuln_type} 分析逻辑自相矛盾 (False+FOUND)，自动修正决策为 give_up")
            return "give_up"
        return decision

    async def _generic_strategist_node(self, state: Dict[str, Any], system_prompt: str, vuln_type: str) -> dict:
        """通用生成器节点逻辑"""
        user_context = {
            "url": state["target_url"],
            "points": state["potential_points"],
            "feedback": state.get("analysis_feedback"),
            "full_request": {
                "method": state["method"],
                "url": state["target_url"],
                "headers": state["headers"],
                "body": state.get("body")
            }
        }
        test_cases = self.strategist.generate(
            vuln_type=vuln_type,
            system_prompt=system_prompt,
            user_context=user_context,
            request_id=state["request_id"]
        )
        return {"test_results": test_cases}

    async def _generic_analyzer_node(
        self, 
        state: Dict[str, Any], 
        prompt: ChatPromptTemplate, 
        results_summary: List[Dict[str, Any]], 
        vuln_type: str, 
        findings_type: str,
        agent_name: str
    ) -> dict:
        """通用分析器节点逻辑"""
        chain = prompt | self.audited_llm.llm
        
        # 准备 LLM 输入
        inputs = {"results": json.dumps(results_summary)}
        if "orig" in prompt.input_variables:
            inputs["orig"] = state.get("response_body", "")[:500]

        # 调用 LLM
        response = await self.audited_llm.ainvoke(
            chain=chain,
            inputs=inputs,
            agent_name=agent_name,
            task_id=state["request_id"],
            prompt_template=prompt
        )
        
        analysis = self._safe_json_parse(response.content)
        is_vulnerable = analysis.get("is_vulnerable", False)
        reasoning = analysis.get("reasoning", "No reasoning provided")
        decision = self._validate_decision(is_vulnerable, analysis.get("decision", "give_up"), vuln_type)
        
        logger.info(f"{vuln_type} 分析完成 | 漏洞: {is_vulnerable} | 决策: {decision} | 原因: {reasoning}")

        findings = []
        if is_vulnerable:
            findings.append({
                "type": findings_type,
                "url": state["target_url"],
                "parameter": analysis.get("vulnerable_parameter"),
                "payload": analysis.get("payload"),
                "evidence": reasoning,
                "original_request": {
                    "method": state["method"],
                    "url": state["target_url"],
                    "headers": state["headers"],
                    "body": state.get("body")
                }
            })
            logger.success(f"发现 {vuln_type} 漏洞! 参数: {analysis.get('vulnerable_parameter')}")

        # 仅在决定重试时才增加计数器
        new_retry_count = state.get(self.retry_key, 0)
        if decision == "retry":
            new_retry_count += 1

        return {
            "next_step": decision,
            "is_vulnerable": is_vulnerable,
            self.retry_key: new_retry_count,
            "analysis_feedback": [reasoning] if decision == "retry" else [],
            "proof_of_concept": f"Found on {analysis.get('vulnerable_parameter')}" if is_vulnerable else None,
            "findings": findings
        }
