from langgraph.graph import StateGraph, END
from src.agents.fuzz.state import FuzzState
from src.agents.fuzz.nodes import FuzzNodes

def create_fuzz_graph():
    nodes = FuzzNodes()
    workflow = StateGraph(FuzzState)

    # 添加节点
    workflow.add_node("analyze_points", nodes.analyze_points_node)
    workflow.add_node("generate_payloads", nodes.strategist_node)
    workflow.add_node("execute_tests", nodes.executor_node)
    workflow.add_node("analyze_results", nodes.analyzer_node)

    # 定义边
    workflow.set_entry_point("analyze_points")
    
    workflow.add_edge("analyze_points", "generate_payloads")
    workflow.add_edge("generate_payloads", "execute_tests")
    workflow.add_edge("execute_tests", "analyze_results")
    
    # 条件边：根据分析结果决定是否重试或结束
    workflow.add_conditional_edges(
        "analyze_results",
        nodes.should_retry,
        {
            "retry": "generate_payloads",
            "end": END
        }
    )

    return workflow.compile()

fuzz_graph = create_fuzz_graph()
