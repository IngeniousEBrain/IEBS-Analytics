from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError('The Username field must be set')

        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        user = self.create_user(username, password=password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class Project(models.Model):
    code = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=255)
    created_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class UserProjectAssociation(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='project_associations')
    projects = models.ManyToManyField(Project)
    assigned_time = models.DateTimeField(auto_now=True)
    updated_assigned_time = models.DateTimeField(auto_now=True)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    created_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(auto_now=True)
    CLIENT = 'client'
    PROJECT_MANAGER = 'project_manager'
    KEY_ACCOUNT_HOLDER = 'key_account_holder'
    ROLE_CHOICES = [
        (CLIENT, 'Client'),
        (PROJECT_MANAGER, 'project_manager'),
        (KEY_ACCOUNT_HOLDER, 'key_account_holder'),
    ]
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name='customuser_set',
        related_query_name='user'
    )
    roles = models.CharField(max_length=20, choices=ROLE_CHOICES, default=CLIENT)
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='customuser_set',
        related_query_name='user'
    )
    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username
