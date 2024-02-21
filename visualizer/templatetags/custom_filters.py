# custom_filters.py
from django import template
from django.template.defaultfilters import striptags, linebreaksbr
register = template.Library()

@register.filter
def dict_key_sort(value):
    if isinstance(value, dict):
        return sorted(value.items())
    return value

@register.filter
def slice_with_words(value, length):
    # Convert newline characters to <br> and then strip HTML tags from the content
    text = striptags(linebreaksbr(value))

    # Slice the content while preserving complete words
    if len(text) <= length:
        return text
    else:
        words = text[:length].split()
        words.pop()  # Remove the last (potentially incomplete) word
        return ' '.join(words) + '...'