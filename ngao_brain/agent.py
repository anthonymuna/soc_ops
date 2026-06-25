# agent.py
import os
import httpx
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from tools import ALL_TOOLS

QWEN_BASE_URL = os.getenv("QWEN_BASE_URL", "https://10.101.7.72/v1").rstrip('/')
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "57be7935b6f361750802cd937f3252d21ce14eab9b8acfcf9a40e53e7cf13486")
QWEN_MODEL = os.getenv("QWEN_MODEL", "Qwen/Qwen2.5-3B-Instruct")

# Initialize ChatOpenAI LLM pointing to the self-hosted Qwen API
llm = ChatOpenAI(
    base_url=QWEN_BASE_URL,
    api_key=QWEN_API_KEY,
    model=QWEN_MODEL,
    temperature=0.1,
    http_client=httpx.Client(verify=False),
)

def get_agent_executor(system_prompt: str) -> AgentExecutor:
    """
    Creates and returns an AgentExecutor with the specified system prompt.
    """
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    
    agent = create_tool_calling_agent(llm, ALL_TOOLS, prompt)
    
    return AgentExecutor(
        agent=agent,
        tools=ALL_TOOLS,
        verbose=True,
        max_iterations=8,
        handle_parsing_errors=True
    )
