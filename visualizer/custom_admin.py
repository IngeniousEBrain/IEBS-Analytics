# custom_admin.py

from django.contrib.admin import AdminSite

class CustomAdminSite(AdminSite):
    login_template = 'admin/login.html'
