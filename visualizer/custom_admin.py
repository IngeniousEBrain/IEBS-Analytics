"""
Module docstring: Define a custom Django AdminSite for the application.
"""

from django.contrib.admin import AdminSite


class CustomAdminSite(AdminSite):
    """
    CustomAdminSite class extending Django's AdminSite.

    Attributes:
        login_template (str): The custom login template for the admin site.

    Methods:
        No additional methods at the moment.

    """
    login_template = 'admin/login.html'
