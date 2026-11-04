def build_prompt(user_input: str) -> str:
    system_prompt = f'You are a helpful assistant. Context: {user_input}'
    return system_prompt
