from typing import Annotated, List, Optional
import operator
from src.agents.manager.state import AgentState, reduce_overwrite, reduce_allow_none

class SQLiState(AgentState):
    """
    SQL 注入专项攻击状态
    """
    # 漏洞分析进展
    potential_points: Annotated[List[str], reduce_overwrite]
    db_type: Annotated[Optional[str], reduce_overwrite]
    
    # 决策逻辑
    next_step: Annotated[str, reduce_overwrite]  # "found", "retry", "give_up"
    sqli_retry_count: Annotated[int, reduce_overwrite]
    analysis_feedback: Annotated[List[str], operator.add] # 记录分析器的反馈，用于指导下一轮生成
    
    # 历史探测执行结果汇总 (用于指导策略进化)
    history_results: Annotated[List[dict], operator.add]
    
    # 计划执行的任务包 (结构化格式)
    # 格式: {"request": {...}, "test_cases": [...]}
    planned_data: Annotated[Optional[dict], reduce_allow_none]
     
    # 当前轮次的测试结果
    test_results: Annotated[List[dict], reduce_overwrite]

    # 攻击结果
    is_vulnerable: Annotated[bool, reduce_overwrite]
    proof_of_concept: Annotated[Optional[str], reduce_overwrite]  # 记录成功的参数和 Payload
