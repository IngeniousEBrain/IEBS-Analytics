from django.shortcuts import render, redirect
from functools import wraps


def validator(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if 'user_id' in request.session:
            return view_func(request, *args, **kwargs)
        else:
            return redirect('login')
    return _wrapped_view
