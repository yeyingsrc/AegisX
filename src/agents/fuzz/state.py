from typing import Annotated, List, Dict, Any, Optional
import operator
from src.agents.manager.state import AgentState, reduce_overwrite, reduce_allow_none

class FuzzState(AgentState):
    """
    Fuzz 模糊测试状态
    """
    # 扫描上下文
    potential_points: Annotated[List[str], reduce_overwrite]  # 待测试参数列表
    history_params: Annotated[List[str], reduce_overwrite]    # 从 Redis 获取的历史参数
    
    # 执行状态
    analysis_feedback: Annotated[List[str], operator.add] # Analyzer 返回的反馈
    history_results: Annotated[List[dict], operator.add]
    fuzz_retry_count: Annotated[int, reduce_overwrite]             # 当前重试次数
    
    # 计划执行的任务包 (结构化格式)
    planned_data: Annotated[Optional[dict], reduce_allow_none]
     
    # 当前轮次的测试结果
    test_results: Annotated[List[dict], reduce_overwrite]

    # 结果输出
    # findings 已经在 AgentState 中定义，这里不需要重复定义，或者保持一致
    status: Annotated[str, reduce_overwrite]                  # 任务状态: running, completed, failed
    
    next_step: Annotated[str, reduce_overwrite]

