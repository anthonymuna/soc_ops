# tools package initializer
from .query_alerts import query_alerts
from .ip_reputation import get_ip_reputation
from .correlate_agent import correlate_agent_history
from .propose_block import propose_block
from .execute_action import execute_approved_action

ALL_TOOLS = [
    query_alerts,
    get_ip_reputation,
    correlate_agent_history,
    propose_block,
    execute_approved_action
]
