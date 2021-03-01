from . import memory_sanitizer
from . import smm_callout_sanitizer

from .base_sanitizer import base_sanitizer

def get_available_sanitizers():
    
    def get_all_subclasses(cls):
        all_subclasses = []

        for subclass in cls.__subclasses__():
            if not get_all_subclasses(subclass):            
                all_subclasses.append(subclass)
            else:
                all_subclasses.extend(get_all_subclasses(subclass))

        return all_subclasses

    return { subcls.NAME:subcls for subcls in get_all_subclasses(base_sanitizer) }

def get(name):
    return get_available_sanitizers()[name]