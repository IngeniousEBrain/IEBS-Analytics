"""
schema for User and Project.
"""
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.db.models.signals import pre_save
from django.dispatch import receiver
from ckeditor.fields import RichTextField
from django.db.models import JSONField
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


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    CustomUser
    """
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    company_name = models.CharField(max_length=250, null=True, blank=True, default='XYZ')
    company_logo = models.ImageField(upload_to='company_logo/', null=True, blank=True)
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
    HI_IP = 'HI_IP'
    HC_IP = 'HC_IP'
    HC_BI = 'HC_BI'
    CFH = 'CFH'
    BD = 'BD'
    SPMT = 'SPMT'
    BU_CHOICES = [
        (HI_IP, 'HI_IP'),
        (HC_IP, 'HC_IP'),
        (HC_BI, 'HC_BI'),
        (BD, 'BD'),
        (SPMT, 'SPMT'),
        (CFH, 'CFH'),
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
    business_unit = models.CharField(max_length=50, choices=BU_CHOICES, default=HI_IP)
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

    code = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=512)
    description = RichTextField(null=True, blank=True)
    previous_info = RichTextField(null=True,blank=True)
    geographical_coverage = models.CharField(max_length=200, null=True,blank=True)
    scope = RichTextField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=IN_PROGRESS)
    created_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(auto_now=True)
    objects = models.Manager()
    def __str__(self):
        """
        Return a string representation of the Project.

        Returns:
            str: String representation of the Project instance.

        """
        return str(self.name)


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
    objects = models.Manager()
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
        return f"Manager: {user_username} || Projects: {', '.join(project_names)}"


class ClientProjectAssociation(models.Model):
    """
    Model representing the association between a client and multiple projects.

    Attributes:
        client (CustomUser): The client associated with the projects.
        projects (ManyToManyField): The projects associated with the client.
        assigned_time (DateTimeField): The timestamp when the association was initially created.
        updated_assigned_time (DateTimeField): The timestamp when the association was last updated.

    Methods:
        __str__(): String representation of the ClientProjectAssociation instance.

    """
    client = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                               related_name='client_project_associations')
    projects = models.ManyToManyField(Project)
    allocated_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                                     related_name='allocated_by_project', null=True, blank=True)
    deallocated_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                                       related_name='deallocated_by_project', null=True, blank=True)
    allocation_time = models.DateTimeField(auto_now=True, null=True, blank=True)
    deallocation_time = models.DateTimeField(null=True, blank=True)
    updated_assigned_time = models.DateTimeField(auto_now=True)
    objects = models.Manager()
    def __str__(self):
        """
        Return a string representation of the ClientProjectAssociation.

        The string includes the username of the associated client and the names of
        the associated projects.

        Returns:
            str: String representation of the ClientProjectAssociation.
        """
        client_username = str(self.client.username) if self.client else "None"
        project_names = [str(project.name) for project in self.projects.all()]
        return f"Client: {client_username} || Projects: {', '.join(project_names)}"


class KeyAccountManagerProjectAssociation(models.Model):
    """
    Model representing the association between a key account manager and multiple projects.

    Attributes:
        key_account_manager (CustomUser): The key account manager associated with the projects.
        projects (ManyToManyField): The projects associated with the key account manager.
        assigned_time (DateTimeField): The timestamp when the association was initially created.
        updated_assigned_time (DateTimeField): The timestamp when the association was last updated.

    Methods:
        __str__(): String representation of the KeyAccountManagerProjectAssociation instance.

    """
    key_account_manager = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                                            related_name='key_account_manager_project_associations')
    projects = models.ManyToManyField(Project)
    assigned_time = models.DateTimeField(auto_now=True)
    updated_assigned_time = models.DateTimeField(auto_now=True)
    objects = models.Manager()
    def __str__(self):
        """
        Return a string representation of the KeyAccountManagerProjectAssociation.

        The string includes the username of the associated key account manager and the names of
        the associated projects.

        Returns:
            str: String representation of the KeyAccountManagerProjectAssociation.
        """
        kam_username = str(self.key_account_manager.username) if self.key_account_manager else "None"
        project_names = [str(project.name) for project in self.projects.all()]
        return f"Key Account Manager: {kam_username} || Projects: {', '.join(project_names)}"


class PatentData(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE,
                             related_name='patent_user')
    project_code = models.CharField(max_length=100)
    publication_number = models.CharField(max_length=50)
    assignee_standardized = models.CharField(max_length=1025)
    legal_status = models.CharField(max_length=50)
    expected_expiry_dates = models.DateField(null=True, blank=True)
    remaining_life = models.PositiveIntegerField(null=True, blank=True)
    cited_patents_count = models.PositiveIntegerField(null=True, blank=True)
    citing_patents_count = models.PositiveIntegerField(null=True, blank=True)
    inventors = models.TextField()
    earliest_patent_priority_date = models.DateField(null=True, blank=True)
    application_dates = models.DateField(null=True, blank=True)
    publication_dates = models.DateField(null=True, blank=True)
    application_number = models.CharField(max_length=1025)
    cpc = models.TextField()
    ipc = models.TextField()
    e_fan = models.CharField(max_length=1025)
    priority_country = models.CharField(max_length=1025, null=True, blank=True)
    created_date = models.DateTimeField(default=timezone.now, blank=True, null=True)
    objects = models.Manager()
    def __str__(self):
        return f"{self.assignee_standardized} - {self.publication_number}"


class ProjectReports(models.Model):
    file = models.FileField(upload_to='uploaded_files/')
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=50)
    uploaded_by = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='uploaded_files', null=True,blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='uploaded_files')
    objects = models.Manager()
    def __str__(self):
        return self.file_name

    class Meta:
        verbose_name = 'Project Report'
        verbose_name_plural = 'Project Reports'


class Category(models.Model):
    name = models.CharField(max_length=255)
    project_id = models.ForeignKey(Project, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)
    level = models.IntegerField(default=0)
    value = models.JSONField(null=True, blank=True)
    num_header_levels = models.IntegerField(default=2)
    upload_date = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    objects = models.Manager()
    def __str__(self):
        return self.name

class ChartHeading(models.Model):
    chart_source_id = models.IntegerField()
    heading = models.CharField(max_length=255, default='XYZ')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='chart_project_id')

    objects = models.Manager()

    class Meta:
        db_table = 'visualizer_chartheading'  # Specify the exact table name if it differs from the default

    def __str__(self):
        return f'ChartHeading: {self.heading}'

