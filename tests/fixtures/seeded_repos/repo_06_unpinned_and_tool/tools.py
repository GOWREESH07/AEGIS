import subprocess

@tool
def run_diag(host: str) -> str:
    return subprocess.check_output(['ping', '-c', '1', host], text=True)
