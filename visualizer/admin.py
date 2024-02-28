"""
Django Admin Configuration for CustomUser, Project, and UserProjectAssociation Models.

This module contains the Django admin configuration classes for the CustomUser,
Project, and UserProjectAssociation models.

Classes:
    - CustomUserAdmin: Admin configuration for the CustomUser model.
    - ProjectAdmin: Admin configuration for the Project model.
    - UserProjectAdmin: Admin configuration for the UserProjectAssociation model.

"""
from django.contrib.auth.models import Group, User
from django.contrib import admin
from .models import CustomUser, Project, UserProjectAssociation


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    """
    Admin configuration for the CustomUser model.

    Attributes:
        - list_display: Display fields in the list view.
        - search_fields: Enable search by username and roles.
        - list_filter: Enable filtering by roles.

    Methods:
        - save_model: Override the save_model method to set the password if provided in the form.

    """
    list_display = ('username', 'roles', 'created_date', 'updated_date')
    search_fields = ('username', 'roles')
    list_filter = ('roles',)

    def save_model(self, request, obj, form, change):
        """
        Save the CustomUser model.

        If a password is set in the form, set the password and then save the model.

        Args:
            - request: The request object.
            - obj: The CustomUser instance.
            - form: The form containing user data.
            - change: A boolean indicating whether the user is being modified.

        """
        if form.cleaned_data['password']:
            obj.set_password(form.cleaned_data['password'])
        obj.save()


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    """
    Admin configuration for the Project model.

    Attributes:
        - list_display: Display fields in the list view.
        - list_filter: Enable filtering by project status.
        - search_fields: Enable search by project code and name.

    """
    list_display = ('code', 'name', 'status', 'created_date', 'updated_date')
    list_filter = ('status',)
    search_fields = ('code', 'name')


@admin.register(UserProjectAssociation)
class UserProjectAdmin(admin.ModelAdmin):
    """
    Admin configuration for the UserProjectAssociation model.

    Attributes:
        - list_display: Display fields in the list view.
        - list_filter: Enable filtering by user and projects.
        - search_fields: Enable search by user and projects.

    """
    list_display = ('user',)
    list_filter = ('user', 'projects')
    search_fields = ('projects', 'projects')


# Unregister default Group and User models from admin
admin.site.unregister(Group)
admin.site.unregister(User)
