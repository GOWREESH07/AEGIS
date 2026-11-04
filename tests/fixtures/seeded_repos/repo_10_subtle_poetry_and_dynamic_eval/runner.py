import subprocess
def run_agent_cmd(agent_output: str):
    return subprocess.run(agent_output, shell=True)
