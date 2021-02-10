import os

class ExitEmulation(RuntimeError):
    pass

def exit():
    raise ExitEmulation()

def abort():
    os.abort()

def ignore():
    pass

def _break():
    breakpoint()
