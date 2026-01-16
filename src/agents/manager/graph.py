from langgraph.graph import StateGraph, END
from src.agents.manager.state import AgentState
from src.agents.manager.nodes import ManagerAgent
from src.agents.sqli.graph import sqli_graph
from src.agents.xss.graph import xss_graph
from src.agents.fuzz.graph import fuzz_graph

def create_manager_graph():
    """创建主控图"""
    builder = StateGraph(AgentState)
    manager = ManagerAgent()

    # 添加主节点
    builder.add_node("manager", manager.analyze_request)
    
    # 添加子图节点
    builder.add_node("sqli_worker", sqli_graph)
    builder.add_node("xss_worker", xss_graph)
    builder.add_node("fuzz_worker", fuzz_graph)

    # 设置入口
    builder.set_entry_point("manager")

    # 条件路由
    def route_tasks(state: AgentState):
        destinations = []
        if "sqli" in state["tasks"]:
            destinations.append("sqli_worker")
        if "xss" in state["tasks"]:
            destinations.append("xss_worker")
        if "fuzz" in state["tasks"]:
            destinations.append("fuzz_worker")
            
        return destinations if destinations else END

    builder.add_conditional_edges("manager", route_tasks)
    builder.add_edge("sqli_worker", END)
    builder.add_edge("xss_worker", END)
    builder.add_edge("fuzz_worker", END)

    return builder.compile()

graph = create_manager_graph()
