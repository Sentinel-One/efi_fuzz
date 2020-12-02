from . import uninitialized_memory_tainter
from . import smm_memory_tainter

from .base_tainter import base_tainter

def get_available_tainters():
    
    def get_all_subclasses(cls):
        all_subclasses = []

        for subclass in cls.__subclasses__():
            all_subclasses.append(subclass)
            all_subclasses.extend(get_all_subclasses(subclass))

        return all_subclasses

    return { subcls.NAME:subcls for subcls in get_all_subclasses(base_tainter) }