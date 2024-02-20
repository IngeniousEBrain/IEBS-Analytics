# custom_filters.py
from django import template

register = template.Library()

@register.filter
def dict_key_sort(value):
    if isinstance(value, dict):
        return sorted(value.items())
    return value
