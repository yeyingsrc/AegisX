import json
import httpx
from pathlib import Path
from typing import List, Dict, Optional, Any
from langchain_core.prompts import ChatPromptTemplate
from src.config.settings import settings
from src.core.llm.service import create_audited_llm
from src.core.engine.strategist import GenericStrategist
from src.core.engine.structured_executor import StructuredExecutor
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
        self.executor = StructuredExecutor(proxies=settings.SCAN_PROXY)
        self.audited_llm = create_audited_llm(
            model_name=settings.MODEL_NAME_WORKER,
            api_key=settings.OPENAI_API_KEY,
            api_base=settings.OPENAI_API_BASE,
            model_kwargs={"response_format": {"type": "json_object"}}
        )

    def _load_static_payloads(self, file_path: str) -> List[str]:
        """从文件加载静态 Payload (支持相对路径自动修正)"""
        try:
            # 优先尝试绝对路径或相对于当前工作目录的路径
            full_path = Path(file_path)
            
            # 如果不存在，尝试相对于项目根目录 (假设 src 是根目录下的文件夹)
            if not full_path.exists():
                # 获取当前文件所在目录的父目录的父目录 (即 src 的父目录)
                base_dir = Path(__file__).resolve().parent.parent.parent
                full_path = base_dir / file_path
            
            if full_path.exists():
                with open(full_path, "r", encoding="utf-8") as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    logger.info(f"成功从 {full_path} 加载 {len(payloads)} 个静态 Payloads")
                    return payloads
            else:
                logger.warning(f"Payload 文件不存在: {file_path} (尝试路径: {full_path})")
                return []
        except Exception as e:
            logger.error(f"加载 Payload 文件失败 {file_path}: {e}")
            return []

    def analyze_injection_points(self, state: Dict[str, Any]) -> dict:
        """通用注入点识别：Query 参数 + Body 参数 + RESTful 路径参数"""
        points = [] # 格式: {"name": "id", "value": "1", "type": "query", "placeholder": "{{1}}"}
        
        # 1. 提取 Query 参数
        url = state["target_url"]
        if "?" in url:
            query_str = url.split("?")[1]
            for p in query_str.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    points.append({
                        "name": k,
                        "value": v,
                        "type": "query",
                        "placeholder": f"{{{{{v}}}}}"
                    })
        
        # 2. 提取 Body 参数 (如果存在)
        body = state.get("body")
        if body:
            try:
                # 尝试解析 JSON body
                body_json = json.loads(body)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        points.append({
                            "name": k,
                            "value": str(v),
                            "type": "body_json",
                            "placeholder": f"{{{{{v}}}}}"
                        })
            except:
                # 尝试解析 form-urlencoded body
                for p in body.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        points.append({
                            "name": k,
                            "value": v,
                            "type": "body_form",
                            "placeholder": f"{{{{{v}}}}}"
                        })
        
        # 3. 启发式识别 RESTful 路径参数 (例如 /api/user/123)
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            # 如果路径部分看起来像 ID (纯数字或 UUID 格式)
            if part.isdigit() or (len(part) > 30 and "-" in part):
                points.append({
                    "name": f"path_{i}",
                    "value": part,
                    "type": "path",
                    "placeholder": f"{{{{{part}}}}}"
                })

        logger.info(f"识别到 {len(points)} 个潜在注入点")
        return {
            "potential_points": points,
            "planned_data": None
        }

    async def executor_node(self, state: Dict[str, Any]) -> dict:
        """通用执行器节点"""
        # 从 planned_data 读取结构化任务包
        structured_data = state.get("planned_data")
        if not structured_data:
            logger.warning("没有发现计划中的测试任务 (planned_data 为空)，跳过执行")
            return {"test_results": [], "history_results": []}

        # 执行结构化数据包
        results = await self.executor.execute_structured(structured_data)
        
        # 将结果存入 test_results，并更新历史记录
        return {
            "test_results": results, 
            "history_results": state.get("history_results", []) + results,
            "planned_data": None  # 执行完后清空计划任务
        }

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

    def _build_fuzzed_request(self, state: Dict[str, Any], points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        安全地构造带有 {{value}} 占位符的原始请求包。
        """
        fuzzed_url = state["target_url"]
        fuzzed_body = state.get("body")
        
        # 1. 处理 Path 参数
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(fuzzed_url)
        
        if any(p["type"] == "path" for p in points):
            path_parts = parsed.path.split("/")
            for point in points:
                if point["type"] == "path":
                    try:
                        idx = int(point["name"].split("_")[1])
                        if idx < len(path_parts):
                            path_parts[idx] = point["placeholder"]
                    except: continue
            new_path = "/".join(path_parts)
            parsed = parsed._replace(path=new_path)
            # 立即更新 fuzzed_url
            fuzzed_url = urlunparse(parsed)

        # 2. 处理 Query 参数
        for point in points:
            if point["type"] == "query":
                name, val, placeholder = point["name"], point["value"], point["placeholder"]
                # 匹配 ?name=val 或 &name=val
                for prefix in ["?", "&"]:
                    target = f"{prefix}{name}={val}"
                    replacement = f"{prefix}{name}={placeholder}"
                    if target in fuzzed_url:
                        fuzzed_url = fuzzed_url.replace(target, replacement, 1)
                        break

        # 3. 处理 Body 参数
        if fuzzed_body:
            for point in points:
                name, val, placeholder = point["name"], point["value"], point["placeholder"]
                if point["type"] == "body_form":
                    # 匹配 name=val 或 &name=val
                    for prefix in ["", "&"]:
                        target = f"{prefix}{name}={val}"
                        replacement = f"{prefix}{name}={placeholder}"
                        if target in fuzzed_body:
                            fuzzed_body = fuzzed_body.replace(target, replacement, 1)
                            break
                elif point["type"] == "body_json":
                        targets = [f'"{name}":"{val}"', f'"{name}": "{val}"', f'"{name}":{val}', f'"{name}": {val}']
                        for t in targets:
                            if t in fuzzed_body:
                                # 精确替换该键值对中的值，避免误伤其他相同值的字段
                                replacement = t.replace(val, placeholder, 1)
                                fuzzed_body = fuzzed_body.replace(t, replacement, 1)
                                break

        return {
            "method": state["method"],
            "target_url": fuzzed_url,
            "headers": state["headers"],
            "body": fuzzed_body
        }

    async def _generic_strategist_node(self, state: Dict[str, Any], system_prompt: str, vuln_type: str) -> dict:
        """通用生成器节点逻辑"""
        # 准备历史执行结果摘要 (汇总所有历史轮次)
        history_results_summary = []
        all_history = state.get("history_results", [])
        
        # 如果历史记录过多，只取最近的 30 条记录，避免上下文溢出
        recent_history = all_history[-100:] if len(all_history) > 30 else all_history

        for r in recent_history:
            # 仅保留关键指标，减少 Token 消耗
            history_results_summary.append({
                "parameter": r.get("parameter"),
                "payload": r.get("payload"),
                "status": r.get("status"),
                "elapsed": r.get("elapsed"),
                "len_diff": r.get("len_diff"),
                "similarity": r.get("similarity")
            })

        user_context = {
            "url": state["target_url"],
            "points": [p["name"] for p in state["potential_points"]] if isinstance(state["potential_points"][0], dict) else state["potential_points"],
            "feedback": state.get("analysis_feedback"),
            "history_results": history_results_summary,
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
            request_id=state["request_id"],
            project_name=state.get("project_name", "Default")
        )
        return {"planned_data": test_cases}

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
            prompt_template=prompt,
            project_name=state.get("project_name", "Default")
        )
        
        analysis = self._safe_json_parse(response.content)
        is_vulnerable = analysis.get("is_vulnerable", False)
        reasoning = analysis.get("reasoning", "No reasoning provided")
        decision = self._validate_decision(is_vulnerable, analysis.get("decision", "give_up"), vuln_type)
        
        logger.info(f"{vuln_type} 分析完成 | 漏洞: {is_vulnerable} | 决策: {decision} | 原因: {reasoning}")

        findings = []
        if is_vulnerable:
            finding = {
                "request_id": state["request_id"],
                "type": findings_type,
                "url": state["target_url"],
                "method": state["method"],
                "parameter": analysis.get("vulnerable_parameter"),
                "payload": analysis.get("payload"),
                "evidence": reasoning,
                "severity": "high",
                "full_request": {
                    "method": state["method"],
                    "url": state["target_url"],
                    "headers": state["headers"],
                    "body": state.get("body")
                }
            }
            findings.append(finding)
            logger.success(f"发现 {vuln_type} 漏洞! 参数: {analysis.get('vulnerable_parameter')}")
            
            # 存入 SQLite 数据库
            try:
                from src.utils.db_helper import db_helper
                db_helper.save_vulnerability(state.get("project_name", "Default"), finding)
            except Exception as e:
                logger.error(f"无法将漏洞结果存入数据库: {e}")

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
