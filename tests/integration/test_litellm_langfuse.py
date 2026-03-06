"""
Integration tests for LiteLLM router and Langfuse v3.139 connectivity.

These tests make REAL calls to external services - no mocks.
"""

import pytest
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from agent.model_config import (
    get_model_config,
    create_llm_for_agent_type,
    get_model_for_agent_type,
    get_temperature_for_agent_type,
)
from agent.langfuse_integration import (
    get_langfuse_client,
    get_prompt_manager,
    get_agent_prompt,
    init_langfuse,
)
from agent.agent_factory import get_agent_factory
from agent.state import MicroAgentInput


class TestLiteLLMConfiguration:
    """Test LiteLLM router connectivity and configuration."""

    def test_model_config_loads(self):
        """Verify model configuration loads from environment."""
        config = get_model_config()

        assert config.litellm_base_url == "https://model-router.mcducklabs.com"
        assert config.litellm_api_key is not None
        assert len(config.litellm_api_key) > 0

        print(f"✓ LiteLLM Base URL: {config.litellm_base_url}")
        print(f"✓ LiteLLM API Key: {config.litellm_api_key[:10]}...")

    def test_model_selection(self):
        """Verify model selection for each agent type."""
        assert get_model_for_agent_type("micro") == "claude-sonnet-4-5-20250929"
        assert get_model_for_agent_type("supervisor") == "claude-opus-4-6"
        assert get_model_for_agent_type("synthesis") == "claude-opus-4-6"

        print("✓ Model selection configured correctly")

    def test_temperature_settings(self):
        """Verify temperature configuration."""
        assert get_temperature_for_agent_type("micro") == 0.0
        assert get_temperature_for_agent_type("supervisor") == 0.1
        assert get_temperature_for_agent_type("synthesis") == 0.2

        print("✓ Temperature settings configured correctly")

    def test_create_micro_agent_llm(self):
        """Test creating micro-agent LLM via LiteLLM router."""
        llm = create_llm_for_agent_type("micro")

        assert llm is not None
        assert llm.model_name == "claude-sonnet-4-5-20250929"
        assert llm.temperature == 0.0
        assert "model-router.mcducklabs.com" in llm.openai_api_base

        print(f"✓ Micro-agent LLM created: {llm.model_name} @ {llm.temperature} temp")

    def test_create_supervisor_llm(self):
        """Test creating supervisor LLM via LiteLLM router."""
        llm = create_llm_for_agent_type("supervisor")

        assert llm is not None
        assert llm.model_name == "claude-opus-4-6"
        assert llm.temperature == 0.1

        print(f"✓ Supervisor LLM created: {llm.model_name} @ {llm.temperature} temp")

    def test_litellm_simple_call(self):
        """Test actual API call to LiteLLM router."""
        llm = create_llm_for_agent_type("micro")

        response = llm.invoke("Say 'hello' in one word.")

        assert response is not None
        assert response.content is not None
        assert len(response.content) > 0

        print(f"✓ LiteLLM router responded: '{response.content[:50]}...'")


class TestLangfuseIntegration:
    """Test Langfuse v3.139 connectivity and prompt management."""

    def test_langfuse_client_initialized(self):
        """Verify Langfuse client can be created."""
        client = get_langfuse_client()

        assert client is not None
        print(f"✓ Langfuse client created for: https://langfuse.mcducklabs.com")

    def test_langfuse_auth_check(self):
        """Verify Langfuse authentication works."""
        success = init_langfuse()

        assert success is True
        print("✓ Langfuse authentication successful")

    def test_prompt_manager_created(self):
        """Verify prompt manager initializes."""
        manager = get_prompt_manager()

        assert manager is not None
        assert manager.client is not None
        assert manager._enabled is True

        print("✓ Prompt manager initialized with Langfuse connection")

    def test_fetch_fallback_prompt(self):
        """Test fetching prompt with fallback (may not exist in Langfuse yet)."""
        prompt = get_agent_prompt("dns_block_rate_analyzer")

        assert prompt is not None
        assert len(prompt) > 0
        assert "DNS Block Rate Analysis" in prompt or "NETWORK_KNOWLEDGE" in prompt

        print(f"✓ Prompt fetched: {len(prompt)} chars")
        print(f"  First 100 chars: {prompt[:100]}...")

    def test_fetch_all_dns_agent_prompts(self):
        """Test fetching all DNS micro-agent prompts."""
        agent_types = [
            "dns_block_rate_analyzer",
            "dns_anomaly_detector",
            "dns_threat_intel",
            "dns_query_pattern",
            "dns_client_risk",
        ]

        for agent_type in agent_types:
            prompt = get_agent_prompt(agent_type)
            assert prompt is not None
            assert len(prompt) > 100
            print(f"✓ {agent_type}: {len(prompt)} chars")

    def test_fetch_supervisor_prompt(self):
        """Test fetching DNS supervisor prompt."""
        prompt = get_agent_prompt("dns_security_supervisor")

        assert prompt is not None
        assert len(prompt) > 100
        assert "supervisor" in prompt.lower() or "aggregate" in prompt.lower()

        print(f"✓ DNS supervisor prompt: {len(prompt)} chars")

    def test_create_prompt_in_langfuse(self):
        """Test creating a prompt in Langfuse (write operation)."""
        manager = get_prompt_manager()

        test_prompt = """
You are a test agent.
This is a test prompt created by integration tests.
"""

        success = manager.create_prompt(
            name="test_agent_prompt",
            prompt=test_prompt,
            labels=["test", "integration"],
            config={"temperature": 0.5, "model": "claude-sonnet-4-5-20250929"}
        )

        assert success is True
        print("✓ Test prompt created in Langfuse successfully")


class TestAgentFactory:
    """Test agent factory with real LLM and Langfuse integration."""

    def test_factory_singleton(self):
        """Verify factory is a singleton."""
        factory1 = get_agent_factory()
        factory2 = get_agent_factory()

        assert factory1 is factory2
        print("✓ Agent factory is singleton")

    def test_create_micro_agent_with_tools(self):
        """Test creating and executing a micro-agent with real LLM call."""
        from agent.tools import get_all_tools

        factory = get_agent_factory()
        tools = get_all_tools()

        # Create a simple test agent input
        agent_input = MicroAgentInput(
            agent_id="test_agent_001",
            agent_type="dns_block_rate_analyzer",
            domain="dns_security",
            time_range_hours=1,
            parameters={"test_mode": True}
        )

        # Execute agent (makes real LLM call)
        result = factory.create_micro_agent(agent_input, tools)

        assert result is not None
        assert result.agent_id == "test_agent_001"
        assert result.agent_type == "dns_block_rate_analyzer"
        assert result.domain == "dns_security"
        assert result.status in ["success", "partial", "failed"]

        print(f"✓ Micro-agent executed: {result.status}")
        print(f"  Summary: {result.summary[:100]}...")
        print(f"  Findings: {len(result.findings)}")
        print(f"  Tool calls: {result.metadata.get('tool_calls', 0)}")

    def test_agent_with_actual_query(self):
        """Test agent making actual data queries via tools."""
        from agent.tools import get_all_tools

        factory = get_agent_factory()
        tools = get_all_tools()

        # Create agent that will actually query AdGuard data
        agent_input = MicroAgentInput(
            agent_id="real_query_test",
            agent_type="dns_block_rate_analyzer",
            domain="dns_security",
            time_range_hours=24,
            parameters={}
        )

        result = factory.create_micro_agent(agent_input, tools)

        assert result is not None
        print(f"\n✓ Real query test completed: {result.status}")
        print(f"  Agent summary: {result.summary[:200]}...")

        if result.findings:
            print(f"\n  Findings ({len(result.findings)}):")
            for finding in result.findings[:3]:
                print(f"    - [{finding.severity}] {finding.title}")
                print(f"      Confidence: {finding.confidence:.0%}")


class TestEndToEndIntegration:
    """End-to-end integration tests combining all components."""

    def test_full_stack_connectivity(self):
        """Verify all components are connected and working."""
        print("\n" + "="*60)
        print("FULL STACK CONNECTIVITY TEST")
        print("="*60)

        # 1. Model Config
        config = get_model_config()
        print(f"\n1. Model Config:")
        print(f"   ✓ LiteLLM: {config.litellm_base_url}")
        print(f"   ✓ Micro model: {config.micro_agent_model}")
        print(f"   ✓ Supervisor model: {config.supervisor_model}")

        # 2. Langfuse
        langfuse_ok = init_langfuse()
        print(f"\n2. Langfuse:")
        print(f"   ✓ Connected: {langfuse_ok}")
        print(f"   ✓ Host: https://langfuse.mcducklabs.com")

        # 3. LiteLLM Router
        llm = create_llm_for_agent_type("micro")
        response = llm.invoke("Test message - reply with just 'OK'")
        print(f"\n3. LiteLLM Router:")
        print(f"   ✓ Model: {llm.model_name}")
        print(f"   ✓ Response: {response.content[:50]}")

        # 4. Prompts
        prompt = get_agent_prompt("dns_block_rate_analyzer")
        print(f"\n4. Prompt Management:")
        print(f"   ✓ Fetched prompt: {len(prompt)} chars")

        # 5. Agent Factory
        factory = get_agent_factory()
        print(f"\n5. Agent Factory:")
        print(f"   ✓ Factory initialized: {factory is not None}")

        print("\n" + "="*60)
        print("✓ ALL SYSTEMS OPERATIONAL")
        print("="*60)

        assert config is not None
        assert langfuse_ok is True
        assert response.content is not None
        assert prompt is not None
        assert factory is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
