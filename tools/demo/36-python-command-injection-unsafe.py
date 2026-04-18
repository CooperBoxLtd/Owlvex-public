# Demo fixture 36 - Unsafe Python shell command execution

import subprocess


def search_logs(request):
    term = request.args.get("term")
    return subprocess.run(f"grep {term} /var/log/app.log", shell=True, capture_output=True, text=True)
