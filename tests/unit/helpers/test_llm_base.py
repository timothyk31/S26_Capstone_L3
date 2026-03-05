"""Unit tests for ToolCallingLLM base class."""

import pytest
from unittest.mock import MagicMock, patch, Mock
import json
import requests

from helpers.llm_base import ToolCallingLLM
from schemas import RunCommandResult


@pytest.mark.unit
class TestToolCallingLLM:
    """Test suite for ToolCallingLLM."""

    def setup_method(self):
        """Set up test environment for each test."""
        self.mock_executor = MagicMock()
        self.mock_executor.return_value = {"result": "success", "output": "test output"}
        
        self.llm = ToolCallingLLM(
            model_name="test-model",
            base_url="https://test-api.com/v1",
            api_key="test-key",
            system_prompt="You are a test assistant.",
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "test_tool",
                        "description": "A test tool",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"}
                            },
                            "required": ["command"]
                        }
                    }
                }
            ],
            tool_executor=self.mock_executor
        )

    def test_init(self):
        """Test LLM initialization."""
        assert self.llm.model_name == "test-model"
        assert self.llm.base_url == "https://test-api.com/v1"
        assert self.llm.api_key == "test-key"
        assert self.llm.endpoint == "https://test-api.com/v1/chat/completions"
        assert len(self.llm.tools) == 1

    @patch('requests.post')
    def test_successful_llm_call_no_tools(self, mock_post):
        """Test successful LLM call without tool usage."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Hello, this is a test response.",
                        "tool_calls": None
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        result = self.llm.run_session("Hello, test message.")
        
        assert result == "Hello, this is a test response."
        mock_post.assert_called_once()
        self.mock_executor.assert_not_called()

    @patch('requests.post')
    def test_successful_llm_call_with_tools(self, mock_post):
        """Test successful LLM call with tool usage."""
        # First call - LLM wants to use tool
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "I'll run a command for you.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "test_tool",
                                    "arguments": '{"command": "echo hello"}'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        
        # Second call - LLM responds after tool execution
        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Command executed successfully.",
                        "tool_calls": None
                    }
                }
            ]
        }
        
        mock_post.side_effect = [mock_response_1, mock_response_2]
        
        result = self.llm.run_session("Run echo hello")
        
        assert "combined_output" in result
        assert mock_post.call_count == 2
        self.mock_executor.assert_called_once_with("test_tool", {"command": "echo hello"})

    @patch('requests.post')
    def test_llm_api_error(self, mock_post):
        """Test LLM API error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {
            "error": {
                "message": "Internal server error",
                "type": "server_error"
            }
        }
        mock_post.return_value = mock_response
        
        with pytest.raises(Exception) as exc_info:
            self.llm.run_session("Test message")
        
        assert "server_error" in str(exc_info.value) or "error" in str(exc_info.value)

    @patch('requests.post')
    def test_llm_network_error(self, mock_post):
        """Test network error handling."""
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        with pytest.raises((requests.exceptions.ConnectionError, Exception)):
            self.llm.run_session("Test message")

    @patch('requests.post')
    def test_llm_timeout(self, mock_post):
        """Test timeout handling."""
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")
        
        with pytest.raises((requests.exceptions.Timeout, Exception)):
            self.llm.run_session("Test message")

    @patch('requests.post')
    def test_tool_execution_error(self, mock_post):
        """Test tool execution error handling."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "I'll run a command.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "test_tool",
                                    "arguments": '{"command": "failing_command"}'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        # Make tool executor raise an exception
        self.mock_executor.side_effect = Exception("Tool execution failed")
        
        with pytest.raises(Exception) as exc_info:
            self.llm.run_session("Run failing command")
        
        assert "Tool execution failed" in str(exc_info.value) or "error" in str(exc_info.value)

    @patch('requests.post')
    def test_invalid_tool_arguments(self, mock_post):
        """Test handling of invalid tool arguments."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "I'll run a command.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "test_tool",
                                    "arguments": 'invalid json'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        with pytest.raises((json.JSONDecodeError, Exception)):
            self.llm.run_session("Run command with invalid args")

    @patch('requests.post')
    def test_max_iterations_limit(self, mock_post):
        """Test maximum iterations limit."""
        # Configure LLM with low max iterations
        limited_llm = ToolCallingLLM(
            model_name="test-model",
            base_url="https://test-api.com/v1",
            api_key="test-key",
            system_prompt="Test prompt",
            tools=self.llm.tools,
            tool_executor=self.mock_executor,
            max_tool_iterations=2
        )
        
        # Mock LLM to always request tool calls
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "I need to use a tool.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "test_tool",
                                    "arguments": '{"command": "echo test"}'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        with pytest.raises(Exception) as exc_info:
            limited_llm.run_session("Keep using tools")
        
        assert "max" in str(exc_info.value).lower() or "limit" in str(exc_info.value).lower()

    def test_request_headers(self):
        """Test that proper headers are set for requests."""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "test", "tool_calls": None}}]
            }
            mock_post.return_value = mock_response
            
            self.llm.run_session("test")
            
            call_kwargs = mock_post.call_args[1]
            headers = call_kwargs['headers']
            
            assert headers['Authorization'] == 'Bearer test-key'
            assert headers['Content-Type'] == 'application/json'

    def test_request_payload_structure(self):
        """Test that request payload has correct structure."""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "test", "tool_calls": None}}]
            }
            mock_post.return_value = mock_response
            
            self.llm.run_session("test message")
            
            call_kwargs = mock_post.call_args[1]
            payload = json.loads(call_kwargs['data'])
            
            assert payload['model'] == 'test-model'
            assert len(payload['messages']) >= 2  # system + user message
            assert payload['tools'] == self.llm.tools
            assert 'tool_choice' in payload

    def test_conversation_history_maintained(self):
        """Test that conversation history is maintained across tool calls."""
        with patch('requests.post') as mock_post:
            # First response with tool call
            mock_response_1 = Mock()
            mock_response_1.status_code = 200
            mock_response_1.json.return_value = {
                "choices": [{
                    "message": {
                        "content": "I'll use a tool.",
                        "tool_calls": [{
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "test_tool",
                                "arguments": '{"command": "echo test"}'
                            }
                        }]
                    }
                }]
            }
            
            # Second response after tool execution
            mock_response_2 = Mock()
            mock_response_2.status_code = 200
            mock_response_2.json.return_value = {
                "choices": [{"message": {"content": "Done!", "tool_calls": None}}]
            }
            
            mock_post.side_effect = [mock_response_1, mock_response_2]
            
            result = self.llm.run_session("Use the tool")
            
            # Check second call has conversation history
            second_call_payload = json.loads(mock_post.call_args_list[1][1]['data'])
            messages = second_call_payload['messages']
            
            # Should have: system, user, assistant, tool, assistant
            assert len(messages) >= 4
            assert messages[1]['role'] == 'user'
            assert messages[2]['role'] == 'assistant'
            assert messages[3]['role'] == 'tool'