import os
from dotenv import load_dotenv
from pydantic import BaseModel

from pydantic_ai import Agent, NativeOutput
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

class CityLocation(BaseModel):
    city: str
    country: str

model = OpenAIChatModel(
    model_name=os.getenv('OPENROUTER_MODEL'),
    provider=OpenAIProvider(
        base_url=os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
        api_key=os.getenv('OPENROUTER_API_KEY'),
    ),
)

# Use structured output with strict validation
agent = Agent(
    model,
    output_type=NativeOutput(CityLocation, strict=True),
    system_prompt="You are a helpful assistant that provides location information."
)

prompt = "Where were the Olympics held in 2012?"

result = agent.run_sync(prompt)

# With structured output, result.output is already a CityLocation instance
location: CityLocation = result.output
print(location)

print(result.usage())