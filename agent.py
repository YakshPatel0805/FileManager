from langchain_community.llms import Ollama
from langchain_core.messages import HumanMessage
from langchain_community.document_loaders import TextLoader


class BaseAgent:
    def __init__(self, llm):
        self.llm = llm

    def run(self, input_data):
        raise NotImplementedError


class LoaderAgent(BaseAgent):
    def run(self, text):
        return text


class AnalyzerAgent(BaseAgent):
    def run(self, text):
        print("\n[AnalyzerAgent] Extracting key points...")
        prompt = f"""
        Extract important key points as bullet points.

        TEXT:
        {text}
        """
        response = self.llm.invoke(prompt)
        return response


class SummarizerAgent(BaseAgent):
    def run(self, key_points):
        print("\n[SummarizerAgent] Creating summary...")
        prompt = f"""
        Create a concise summary using these key points:

        {key_points}
        """
        response = self.llm.invoke(prompt)
        return response


class ReviewerAgent(BaseAgent):
    def run(self, summary):
        print("\n[ReviewerAgent] Refining summary...")
        prompt = f"""
        Improve clarity, grammar, and conciseness:

        {summary}
        """
        response = self.llm.invoke(prompt)
        return response


class MultiAgentPipeline:
    def __init__(self, agents):
        self.agents = agents

    def run(self, input_data):
        data = input_data
        for agent in self.agents:
            data = agent.run(data)
        return data


def summarize_text_agent(text: str) -> str:
    llm = Ollama(
        model="gemma:2b",
        temperature=0
    )

    pipeline = MultiAgentPipeline([
        LoaderAgent(llm),
        AnalyzerAgent(llm),
        SummarizerAgent(llm),
        ReviewerAgent(llm)
    ])

    return pipeline.run(text)

