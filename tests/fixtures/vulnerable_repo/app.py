import subprocess
import openai

API_KEY = "sk-ant-api03-abcdef1234567890abcdef1234567890"


def handle_user_task(user_input: str, llm_response: str, vector_store):
    system_prompt = "You are a coding assistant: " + user_input
    vector_store.add_documents([user_input])
    result = eval(llm_response)
    subprocess.run(llm_response, shell=True)
    return result
