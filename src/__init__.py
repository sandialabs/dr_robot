import os


def join_abs(*args):
    return os.path.abspath(os.path.join(*args))
