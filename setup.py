from setuptools import setup, find_packages

setup(
    name="vulnerability_qa",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2",
        "pydantic-ai[openai]>=0.0.15",
        "requests>=2.31.0",
        "python-dotenv>=1.0.1",
        "pytest>=7.0.0",
        "responses>=0.23.0",
        "click>=8.0.0",
        "rich>=13.0.0",
        "pyyaml>=6.0.0",
        "ansible-core>=2.15.0"
    ],
)
