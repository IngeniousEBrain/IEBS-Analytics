"""
file containing decorators
"""
from functools import wraps
from django.shortcuts import redirect


def validator(view_func):
    """
    DECORATOR FOR LOGIN VALIDATION.
    """

    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if 'logged_in_user_id' in request.session:
            return view_func(request, *args, **kwargs)
        return redirect('login')

    return _wrapped_view
