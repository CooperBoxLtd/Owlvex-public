# Demo fixture 37 - Safe Python process invocation

import subprocess


def search_logs(request):
    term = request.args.get("term")
    return subprocess.run(["grep", term, "/var/log/app.log"], shell=False, capture_output=True, text=True)
