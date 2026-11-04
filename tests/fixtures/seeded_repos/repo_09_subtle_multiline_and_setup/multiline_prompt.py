def make_sys_msg(user_input: str) -> dict:
    msg = {
        'role': 'system',
        'content': 'Base instructions: ' + user_input,
    }
    return msg
