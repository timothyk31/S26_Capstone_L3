import json
import os
from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
load_dotenv()
class CityLocation(BaseModel):
    city: str
    country: str


model = OpenAIChatModel(
    model_name=os.getenv('OPENROUTER_MODEL', 'openai/gpt-oss-20b:free'),
    provider=OpenAIProvider(
        base_url=os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
        api_key=os.getenv('OPENROUTER_API_KEY'),
    ),
)
agent = Agent(model)

# Ask for strict JSON so we can parse without tool calling
prompt = (
    "Where were the Olympics held in 2012? "
    "Respond ONLY as a compact JSON object with keys city and country, "
    'e.g. {"city":"London","country":"United Kingdom"}. No extra text.'
)

result = agent.run_sync(prompt)

raw = result.output if isinstance(result.output, str) else str(result.output)
try:
    data = json.loads(raw)
    obj = CityLocation.model_validate(data)
    print(obj)
except (json.JSONDecodeError, ValidationError):
    print("Unexpected response:", raw)

print(result.usage())
#> RunUsage(input_tokens=57, output_tokens=8, requests=1)