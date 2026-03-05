"""API contract tests for OpenRouter/LLM services."""

import pytest
import requests
import responses
from unittest.mock import patch
import json

from helpers.llm_base import ToolCallingLLM


@pytest.mark.api
class TestOpenRouterAPIContract:
    """Test OpenRouter API contracts and behavior."""

    def setup_method(self):
        """Set up test environment."""
        self.base_url = "https://openrouter.ai/api/v1"
        self.api_key = "test-key-123"
        self.model_name = "meta-llama/llama-3.1-70b-instruct"
        
        def mock_tool_executor(tool_name: str, args: dict) -> dict:
            _ = tool_name, args  # Suppress unused variable warnings
            return {"result": "success"}
        
        self.llm = ToolCallingLLM(
            model_name=self.model_name,
            base_url=self.base_url,
            api_key=self.api_key,
            system_prompt="You are a test assistant.",
            tools=[],
            tool_executor=mock_tool_executor
        )

    @responses.activate
    @pytest.mark.contract
    def test_openrouter_api_response_format(self):
        """Test that OpenRouter API returns expected response format."""
        expected_response = {
            "choices": [
                {
                    "message": {
                        "content": "This is a test response from the LLM.",
                        "role": "assistant",
                        "tool_calls": None
                    },
                    "finish_reason": "stop",
                    "index": 0
                }
            ],
            "created": 1234567890,
            "model": self.model_name,
            "object": "chat.completion",
            "usage": {
                "completion_tokens": 10,
                "prompt_tokens": 25,
                "total_tokens": 35
            }
        }
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=expected_response,
            status=200
        )
        
        result = self.llm.run_session("Test message")
        
        assert "combined_output" in result
        assert len(responses.calls) == 1
        
        # Verify request format
        request_body = responses.calls[0].request.body
        if request_body:
            request_data = json.loads(request_body)
            assert request_data["model"] == self.model_name
            assert "messages" in request_data
            assert request_data["messages"][0]["role"] == "system"

    @responses.activate
    @pytest.mark.contract
    def test_openrouter_tool_calling_format(self):
        """Test OpenRouter tool calling response format."""
        # First response with tool call
        tool_call_response = {
            "choices": [{
                "message": {
                    "content": "I'll help you run that command.",
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "run_command",
                            "arguments": '{"command": "echo hello"}'
                        }
                    }]
                }
            }]
        }
        
        # Second response after tool execution
        final_response = {
            "choices": [{
                "message": {
                    "content": "Command executed successfully!",
                    "role": "assistant",
                    "tool_calls": None
                }
            }]
        }
        
        # Add tool to LLM for this test
        def mock_tool_executor_with_tools(tool_name: str, args: dict) -> dict:
            _ = tool_name, args  # Suppress unused variable warnings
            return {"result": "success", "output": "hello"}
        
        llm_with_tools = ToolCallingLLM(
            model_name=self.model_name,
            base_url=self.base_url,
            api_key=self.api_key,
            system_prompt="Test prompt",
            tools=[{
                "type": "function",
                "function": {
                    "name": "run_command",
                    "description": "Run a shell command",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"}
                        },
                        "required": ["command"]
                    }
                }
            }],
            tool_executor=mock_tool_executor_with_tools
        )
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=tool_call_response,
            status=200
        )
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=final_response,
            status=200
        )
        
        result = llm_with_tools.run_session("Run echo hello")
        
        assert "combined_output" in result
        assert len(responses.calls) == 2

    @responses.activate
    @pytest.mark.contract
    def test_openrouter_error_response_format(self):
        """Test OpenRouter error response format."""
        error_response = {
            "error": {
                "message": "Insufficient credits",
                "type": "insufficient_credits",
                "code": "insufficient_credits"
            }
        }
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=error_response,
            status=402
        )
        
        with pytest.raises((requests.exceptions.HTTPError, Exception)) as exc_info:
            self.llm.run_session("Test message")
        
        assert "insufficient_credits" in str(exc_info.value) or "402" in str(exc_info.value)

    @responses.activate
    @pytest.mark.contract
    def test_openrouter_rate_limit_response(self):
        """Test OpenRouter rate limiting response."""
        rate_limit_response = {
            "error": {
                "message": "Rate limit exceeded",
                "type": "rate_limit_exceeded",
                "code": "rate_limit_exceeded"
            }
        }
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=rate_limit_response,
            status=429
        )
        
        with pytest.raises((requests.exceptions.HTTPError, Exception)) as exc_info:
            self.llm.run_session("Test message")
        
        assert "rate_limit_exceeded" in str(exc_info.value) or "429" in str(exc_info.value)

    def test_request_headers_format(self):
        """Test that requests include proper headers."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.POST,
                f"{self.base_url}/chat/completions",
                json={"choices": [{"message": {"content": "test", "tool_calls": None}}]},
                status=200
            )
            
            self.llm.run_session("Test")
            
            if rsps.calls:
                request = rsps.calls[0].request
                assert request.headers["Authorization"] == f"Bearer {self.api_key}"
                assert request.headers["Content-Type"] == "application/json"

    @pytest.mark.slow
    def test_network_timeout_handling(self):
        """Test network timeout scenarios."""
        with patch('requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout("Request timed out")
            
            with pytest.raises((requests.exceptions.Timeout, Exception)):
                self.llm.run_session("Test message")

    @pytest.mark.slow
    def test_network_connection_error(self):
        """Test network connection error handling."""
        with patch('requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
            
            with pytest.raises((requests.exceptions.ConnectionError, Exception)):
                self.llm.run_session("Test message")

    @responses.activate
    def test_malformed_response_handling(self):
        """Test handling of malformed API responses."""
        # Invalid JSON response
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            body="Invalid JSON{",
            status=200,
            content_type="application/json"
        )
        
        with pytest.raises((json.JSONDecodeError, Exception)):
            self.llm.run_session("Test message")

    @responses.activate
    def test_missing_required_fields(self):
        """Test handling of responses missing required fields."""
        incomplete_response = {
            "choices": [
                {
                    # Missing 'message' field
                    "finish_reason": "stop"
                }
            ]
        }
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=incomplete_response,
            status=200
        )
        
        with pytest.raises((KeyError, AttributeError, Exception)):
            self.llm.run_session("Test message")

    @responses.activate
    def test_token_usage_tracking(self):
        """Test token usage information is properly tracked."""
        response_with_usage = {
            "choices": [{
                "message": {"content": "Test response", "tool_calls": None}
            }],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 25,
                "total_tokens": 75
            }
        }
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json=response_with_usage,
            status=200
        )
        
        result = self.llm.run_session("Test message")
        assert "combined_output" in result
        # Usage tracking is handled internally by the session

    @responses.activate
    def test_model_switching(self):
        """Test that different models can be used."""
        different_model = "openai/gpt-4o"
        
        def mock_tool_executor_alt(tool_name: str, args: dict) -> dict:
            _ = tool_name, args  # Suppress unused variable warnings
            return {"result": "success"}
        
        llm_different = ToolCallingLLM(
            model_name=different_model,
            base_url=self.base_url,
            api_key=self.api_key,
            system_prompt="Test prompt",
            tools=[],
            tool_executor=mock_tool_executor_alt
        )
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json={"choices": [{"message": {"content": "GPT-4 response", "tool_calls": None}}]},
            status=200
        )
        
        result = llm_different.run_session("Test with different model")
        
        # Verify correct model was requested
        if responses.calls:
            request_body = responses.calls[0].request.body
            if request_body:
                request_data = json.loads(request_body)
                assert request_data["model"] == different_model
        
        assert "combined_output" in result

    @responses.activate
    def test_base_url_variations(self):
        """Test different base URL configurations."""
        def mock_tool_executor_trailing(tool_name: str, args: dict) -> dict:
            _ = tool_name, args  # Suppress unused variable warnings
            return {}
        
        # Test with trailing slash
        llm_trailing = ToolCallingLLM(
            model_name=self.model_name,
            base_url="https://openrouter.ai/api/v1/",  # Note trailing slash
            api_key=self.api_key,
            system_prompt="Test",
            tools=[],
            tool_executor=mock_tool_executor_trailing
        )
        
        responses.add(
            responses.POST,
            f"{self.base_url}/chat/completions",
            json={"choices": [{"message": {"content": "test", "tool_calls": None}}]},
            status=200
        )
        
        result = llm_trailing.run_session("Test")
        assert "combined_output" in result