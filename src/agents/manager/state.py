from typing import Annotated, List, TypedDict, Optional
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
import operator

def reduce_overwrite(left, right):
    """
    通用覆盖策略：忽略 None 值，防止意外覆盖。
    """
    if right is None:
        return left
    return right

def reduce_allow_none(left, right):
    """
    允许 None 的覆盖策略：用于需要显式清空的字段（如 planned_data）。
    """
    return right

class AgentState(TypedDict):
    """
    全局 Agent 状态定义
    """
    # 原始请求信息 (来自拦截器)
    request_id: Annotated[str, reduce_overwrite]
    project_name: Annotated[str, reduce_overwrite] # 新增：项目名称
    target_url: Annotated[str, reduce_overwrite]
    method: Annotated[str, reduce_overwrite]
    headers: Annotated[dict, reduce_overwrite]
    body: Annotated[Optional[str], reduce_overwrite]
    
    # 原始响应信息 (如果可用)
    response_headers: Annotated[Optional[dict], reduce_overwrite]
    response_body: Annotated[Optional[str], reduce_overwrite]
    
    # 任务分发状态
    tasks: Annotated[List[str], reduce_overwrite]  # 例如: ["sqli", "xss"]
    
    # 消息记录 (用于 LangGraph 内部通信)
    messages: Annotated[List[BaseMessage], add_messages]

    # 漏洞发现汇总
    findings: Annotated[List[dict], operator.add]
