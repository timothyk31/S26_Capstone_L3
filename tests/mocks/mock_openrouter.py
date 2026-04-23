"""Mock OpenRouter API server for testing."""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs


class MockOpenRouterHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock OpenRouter API."""
    
    def __init__(self, *args, response_config=None, **kwargs):
        self.response_config = response_config or {}
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests to /chat/completions."""
        if self.path == '/chat/completions':
            self._handle_chat_completions()
        else:
            self._send_error(404, "Not Found")
    
    def _handle_chat_completions(self):
        """Handle chat completions endpoint."""
        try:
            # Parse request
            content_length = int(self.headers.get('Content-Length', 0))
            request_body = self.rfile.read(content_length)
            request_data = json.loads(request_body.decode('utf-8'))
            
            # Validate auth
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self._send_error(401, "Unauthorized")
                return
            
            # Check for configured responses
            model = request_data.get('model')
            if model in self.response_config.get('model_responses', {}):
                response = self.response_config['model_responses'][model]
                self._send_json_response(200, response)
                return
            
            # Default successful response
            messages = request_data.get('messages', [])
            tools = request_data.get('tools', [])
            
            # Simulate tool calling if tools are provided
            if tools and len(messages) > 1:
                user_message = next((m for m in messages if m['role'] == 'user'), {})
                user_content = user_message.get('content', '').lower()
                
                # Simple keyword-based tool calling simulation
                if 'run' in user_content or 'execute' in user_content or 'command' in user_content:
                    tool_call_response = {
                        "choices": [{
                            "message": {
                                "content": "I'll run that command for you.",
                                "role": "assistant",
                                "tool_calls": [{
                                    "id": "call_123abc",
                                    "type": "function",
                                    "function": {
                                        "name": tools[0]["function"]["name"],
                                        "arguments": json.dumps({"command": "echo hello"})
                                    }
                                }]
                            },
                            "finish_reason": "tool_calls",
                            "index": 0
                        }],
                        "model": model,
                        "usage": {
                            "prompt_tokens": 50,
                            "completion_tokens": 25,
                            "total_tokens": 75
                        }
                    }
                    self._send_json_response(200, tool_call_response)
                    return
            
            # Check if this is a follow-up after tool execution
            tool_messages = [m for m in messages if m['role'] == 'tool']
            if tool_messages:
                final_response = {
                    "choices": [{
                        "message": {
                            "content": "Command executed successfully!",
                            "role": "assistant",
                            "tool_calls": None
                        },
                        "finish_reason": "stop",
                        "index": 0
                    }],
                    "model": model,
                    "usage": {
                        "prompt_tokens": 75,
                        "completion_tokens": 15,
                        "total_tokens": 90
                    }
                }
                self._send_json_response(200, final_response)
                return
            
            # Standard response without tool calls
            standard_response = {
                "choices": [{
                    "message": {
                        "content": "This is a mock response from the OpenRouter API.",
                        "role": "assistant",
                        "tool_calls": None
                    },
                    "finish_reason": "stop",
                    "index": 0
                }],
                "created": int(time.time()),
                "model": model,
                "object": "chat.completion",
                "usage": {
                    "prompt_tokens": 30,
                    "completion_tokens": 20,
                    "total_tokens": 50
                }
            }
            
            self._send_json_response(200, standard_response)
            
        except json.JSONDecodeError:
            self._send_error(400, "Invalid JSON")
        except Exception as e:
            self._send_error(500, f"Internal server error: {str(e)}")
    
    def _send_json_response(self, status_code, data):
        """Send JSON response."""
        response_json = json.dumps(data)
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_json)))
        self.end_headers()
        self.wfile.write(response_json.encode('utf-8'))
    
    def _send_error(self, status_code, message):
        """Send error response."""
        error_response = {
            "error": {
                "message": message,
                "type": "api_error",
                "code": "error"
            }
        }
        self._send_json_response(status_code, error_response)
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class MockOpenRouterServer:
    """Mock OpenRouter API server for testing."""
    
    def __init__(self, port=8000, response_config=None):
        """Initialize mock server.
        
        Args:
            port: Port to run server on
            response_config: Dictionary with custom response configurations
        """
        self.port = port
        self.response_config = response_config or {}
        self.server = None
        self.thread = None
        
    def start(self):
        """Start the mock server in a background thread."""
        def create_handler(*args, **kwargs):
            return MockOpenRouterHandler(*args, response_config=self.response_config, **kwargs)
        
        self.server = HTTPServer(('localhost', self.port), create_handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait a moment for server to start
        time.sleep(0.1)
    
    def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)
    
    def get_url(self):
        """Get the base URL for the mock server."""
        return f"http://localhost:{self.port}"
    
    def configure_response(self, model, response):
        """Configure a custom response for a specific model."""
        if 'model_responses' not in self.response_config:
            self.response_config['model_responses'] = {}
        self.response_config['model_responses'][model] = response
    
    def configure_error_response(self, model, error_code, error_message):
        """Configure an error response for a specific model."""
        error_response = {
            "error": {
                "message": error_message,
                "type": "api_error",
                "code": error_code
            }
        }
        self.configure_response(model, error_response)


# Context manager for easy testing
class MockOpenRouterContext:
    """Context manager for mock OpenRouter server."""
    
    def __init__(self, port=8001, response_config=None):
        self.server = MockOpenRouterServer(port=port, response_config=response_config)
    
    def __enter__(self):
        self.server.start()
        return self.server
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.stop()


# Example usage configurations
EXAMPLE_CONFIGURATIONS = {
    'rate_limited': {
        'model_responses': {
            'meta-llama/llama-3.1-70b-instruct': {
                "error": {
                    "message": "Rate limit exceeded",
                    "type": "rate_limit_exceeded",
                    "code": "rate_limit_exceeded"
                }
            }
        }
    },
    
    'insufficient_credits': {
        'model_responses': {
            'openai/gpt-4o': {
                "error": {
                    "message": "Insufficient credits",
                    "type": "insufficient_credits",
                    "code": "insufficient_credits"
                }
            }
        }
    },
    
    'tool_calling_success': {
        'model_responses': {
            'test-model': {
                "choices": [{
                    "message": {
                        "content": "I'll help you with that command.",
                        "role": "assistant",
                        "tool_calls": [{
                            "id": "call_test123",
                            "type": "function",
                            "function": {
                                "name": "run_command",
                                "arguments": '{"command": "echo test"}'
                            }
                        }]
                    }
                }]
            }
        }
    }
}


if __name__ == "__main__":
    # Simple test of the mock server
    print("Starting mock OpenRouter server on port 8002...")
    
    with MockOpenRouterContext(port=8002) as server:
        print(f"Mock server running at {server.get_url()}")
        print("Test with: curl -X POST http://localhost:8002/chat/completions -H 'Authorization: Bearer test' -d '{\"model\":\"test\",\"messages\":[]}'")
        
        try:
            input("Press Enter to stop the server...")
        except KeyboardInterrupt:
            pass
    
    print("Mock server stopped.")