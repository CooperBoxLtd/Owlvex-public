# Demo fixture 40 - Unsafe Python path join

import os


def download(request):
    filename = request.args.get("file")
    target = os.path.join("/srv/files", filename)
    return open(target).read()
