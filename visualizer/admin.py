from django.contrib import admin
from django.contrib.auth.hashers import make_password
from .models import CustomUser, Project

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'project_code', 'roles', 'created_date', 'updated_date')
    search_fields = ('username', 'project_code', 'roles')
    list_filter = ('roles',)

    def save_model(self, request, obj, form, change):
        # Check if a password is set in the form
        if form.cleaned_data['password']:
            obj.set_password(form.cleaned_data['password'])
        obj.save()

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'created_date', 'updated_date')
    search_fields = ('code', 'name')
