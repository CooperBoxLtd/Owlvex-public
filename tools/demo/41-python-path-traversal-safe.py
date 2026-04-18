# Demo fixture 41 - Safe Python file lookup

import os


def download():
    target = os.path.join("/srv/files", "logo.png")
    return open(target).read()
