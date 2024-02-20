"""
schema for User and Project.
"""
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.db.models.signals import pre_save
from django.dispatch import receiver
from ckeditor.fields import RichTextField
import logging


logger = logging.getLogger(__name__)


class CustomUserManager(BaseUserManager):
    """
    Custom manager for the CustomUser model.

    This manager provides methods to create a regular user and a superuser.

    Methods:
    - create_user(username, password=None, **extra_fields): Creates a regular user.
    - create_superuser(username, password=None, **extra_fields): Creates a superuser.

    """

    def create_user(self, username, password=None, **extra_fields):
        """
        Create and return a regular user with the given username and password.

        Args:
            username (str): The username for the user.
            password (str): The password for the user. If not provided,
            the user will have no password.
            **extra_fields: Additional fields to be saved with the user.

        Returns:
            CustomUser: The created user object.

        Raises:
            ValueError: If the provided username is empty.

        """
        if not username:
            raise ValueError('The Username field must be set')
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        """
        Create and return a superuser with the given username and password.

        Args:
            username (str): The username for the superuser.
            password (str): The password for the superuser. If not provided,
            the superuser will have no password.
            **extra_fields: Additional fields to be saved with the superuser.

        Returns:
            CustomUser: The created superuser object.

        """
        user = self.create_user(username, password=password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class Project(models.Model):
    """
    Model representing a project.

    Attributes:
        code (CharField): The unique code for the project.
        name (CharField): The name of the project.
        description (TextField): The description of the project.
        status (CharField): The status of the project, chosen from predefined choices.
        created_date (DateTimeField): The timestamp when the project was created.
        updated_date (DateTimeField): The timestamp when the project was last updated.

    Methods:
        __str__(): String representation of the Project instance.

    """
    objects = None
    COMPLETED = 'Completed'
    IN_PROGRESS = 'In Progress'

    STATUS_CHOICES = [
        (COMPLETED, 'Completed'),
        (IN_PROGRESS, 'In Progress')
    ]

    code = models.CharField(max_length=100, unique=True, blank=True, editable=False)
    name = models.CharField(max_length=255)
    description = RichTextField()
    scope = RichTextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=IN_PROGRESS)
    created_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        """
        Return a string representation of the Project.

        Returns:
            str: String representation of the Project instance.

        """
        return str(self.name)


@receiver(pre_save, sender=Project)
def generate_project_code(sender, instance, **kwargs):
    if instance._state.adding:
        # First time creation
        current_year = timezone.now().year
        financial_year_start_month = 4

        if timezone.now().month < financial_year_start_month:
            current_year -= 1

        last_project = Project.objects.last()

        if last_project:
            counter = int(last_project.code[-4:])
            next_counter = counter + 1
        else:
            next_counter = 1

        instance.code = f"IEBS2023{str(next_counter).zfill(4)}"

    else:
        if instance.code:
            return


pre_save.connect(generate_project_code, sender=Project)


class UserProjectAssociation(models.Model):
    """
    Model representing the association between a user and multiple projects.

    Attributes:
        user (CustomUser): The user associated with the projects.
        projects (ManyToManyField): The projects associated with the user.
        assigned_time (DateTimeField): The timestamp when the association was initially created.
        updated_assigned_time (DateTimeField): The timestamp when the association was last updated.

    Methods:
        __str__(): String representation of the UserProjectAssociation instance.

    """

    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                             related_name='project_associations')
    projects = models.ManyToManyField(Project)
    assigned_time = models.DateTimeField(auto_now=True)
    updated_assigned_time = models.DateTimeField(auto_now=True)

    def __str__(self):
        """
        Return a string representation of the UserProjectAssociation.

        The string includes the username of the associated user and the names of
        the associated projects.

        Returns:
            str: String representation of the UserProjectAssociation.
        """
        user_username = str(self.user.username) if self.user else "None"
        project_names = [str(project.name) for project in self.projects.all()]
        return f"User: {user_username}, Projects: {', '.join(project_names)}"


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    CustomUser
    """
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
        help_text='The groups this user belongs to. A user will get '
                  'all permissions granted to each of their groups.',
        related_name='custom_user_set',
        related_query_name='user'
    )
    roles = models.CharField(max_length=20, choices=ROLE_CHOICES, default=CLIENT)
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='custom_user_set',
        related_query_name='user'
    )
    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __str__(self):
        return str(self.username)


class PatentData(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                             related_name='patent_user')
    project_code = models.CharField(max_length=50)
    publication_number = models.CharField(max_length=50)
    assignee_standardized = models.CharField(max_length=200)
    legal_status = models.CharField(max_length=50)
    expected_expiry_dates = models.DateField(null=True, blank=True)
    remaining_life = models.PositiveIntegerField(null=True, blank=True)
    cited_patents_count = models.PositiveIntegerField(null=True, blank=True)
    citing_patents_count = models.PositiveIntegerField(null=True, blank=True)
    inventors = models.TextField()
    earliest_patent_priority_date = models.DateField(null=True, blank=True)
    application_dates = models.DateField(null=True, blank=True)
    publication_dates = models.DateField(null=True, blank=True)
    application_number = models.CharField(max_length=255)
    cpc = models.TextField()
    ipc = models.TextField()
    e_fan = models.CharField(max_length=100)
    priority_country = models.CharField(max_length=100,null=True, blank=True)
    created_date = models.DateTimeField(default=timezone.now, blank=True, null=True)

    def __str__(self):
        return f"{self.assignee_standardized} - {self.publication_number}"
