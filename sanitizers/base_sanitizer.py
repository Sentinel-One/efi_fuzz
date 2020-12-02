import os
from abc import ABC, abstractmethod

class base_sanitizer():

    def __init__(self, ql):
        self.ql = ql

    @property
    @staticmethod
    @abstractmethod
    def NAME():
        pass

    @abstractmethod
    def enable(self):
        pass

    def verbose_abort(self):
        self.ql.os.emu_error()
        os.abort()
