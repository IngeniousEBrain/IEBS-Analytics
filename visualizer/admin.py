from django.contrib import admin
from django.contrib.auth.models import Group, User
from .models import CustomUser, Project, UserProjectAssociation


@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'roles', 'created_date', 'updated_date')
    search_fields = ('username', 'roles')
    list_filter = ('roles',)

    def save_model(self, request, obj, form, change):
        # Check if a password is set in the form
        if form.cleaned_data['password']:
            obj.set_password(form.cleaned_data['password'])
        obj.save()


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'status', 'created_date', 'updated_date')
    list_filter = ('status',)
    search_fields = ('code', 'name')


@admin.register(UserProjectAssociation)
class UserProjectAdmin(admin.ModelAdmin):
    list_display = ('user',)
    list_filter = ('user', 'projects')
    search_fields = ('user', 'projects')


admin.site.unregister(Group)
admin.site.unregister(User)
