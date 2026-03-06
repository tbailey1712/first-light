#!/bin/bash
# Run integration tests against real LiteLLM and Langfuse services

set -e

echo "=============================================="
echo "First Light - Integration Tests"
echo "=============================================="
echo ""
echo "Testing against:"
echo "  - LiteLLM: https://model-router.mcducklabs.com"
echo "  - Langfuse: https://langfuse.mcducklabs.com"
echo ""
echo "Note: These tests make REAL API calls (no mocks)"
echo "=============================================="
echo ""

# Check .env file exists
if [ ! -f .env ]; then
    echo "ERROR: .env file not found!"
    echo "Copy .env.example to .env and configure your API keys"
    exit 1
fi

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Check required variables
if [ -z "$LITELLM_BASE_URL" ]; then
    echo "ERROR: LITELLM_BASE_URL not set in .env"
    exit 1
fi

if [ -z "$LANGFUSE_SECRET_KEY" ]; then
    echo "WARNING: LANGFUSE_SECRET_KEY not set - some tests may fail"
fi

# Run tests
echo "Running integration tests..."
echo ""

pytest tests/integration/test_litellm_langfuse.py \
    -v \
    -s \
    --tb=short \
    --color=yes

echo ""
echo "=============================================="
echo "Integration tests complete!"
echo "=============================================="
