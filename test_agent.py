#!/usr/bin/env python3
"""
Test the First Light AI Agent with the new log query tools.
"""

import asyncio
from agent.graph import get_agent
from langchain_core.messages import HumanMessage


async def test_agent():
    """Test the agent with a simple security query."""
    agent = get_agent()

    # Test query
    test_message = "Give me a quick security summary for the last hour. What threats have been blocked?"

    print(f"🤖 Testing First Light AI Agent")
    print(f"📝 Query: {test_message}\n")

    config = {"configurable": {"thread_id": "test-001"}}

    # Stream the response
    print("🔍 Agent Response:\n")
    async for event in agent.astream(
        {"messages": [HumanMessage(content=test_message)]},
        config=config,
        stream_mode="values"
    ):
        # Print the last message in each event
        if "messages" in event and event["messages"]:
            last_msg = event["messages"][-1]
            if hasattr(last_msg, "content") and last_msg.content:
                # Only print if it's the final response (not tool calls)
                if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
                    print(last_msg.content)

    print("\n✅ Test complete!")


if __name__ == "__main__":
    asyncio.run(test_agent())
