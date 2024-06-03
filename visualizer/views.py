"""
Views for the 'visualizer' app.
"""
import os
from django.conf import settings
import json
import math
from collections import Counter
# Django imports
from collections import defaultdict
# Third-party imports
from datetime import datetime
from io import BytesIO
from urllib.parse import unquote
from django.db import transaction
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from django.contrib.auth.hashers import check_password
from django.contrib.sessions.models import Session
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers import serialize
from django.db.models import Count
from django.db.models import Q
from django.db.models.functions import ExtractYear
from django.http import HttpResponse, Http404
from django.http import HttpResponseServerError
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from openpyxl import Workbook
from plotly.subplots import make_subplots
from django.contrib.auth import authenticate
# Local imports
from .models import *
from .packages import request
from django.contrib.auth.models import User


def ie_analytics_home(req):
    """
    Render the home page.

    Parameters:
    - request: HTTP request object

    Returns:
    - Rendered template response
    """
    return render(req, 'pages/onboard/login.html')


@csrf_exempt
def login(req):
    """
    Handle user login.

    Parameters:
    - request (HttpRequest): The HTTP request object containing login data.

    Returns:
    - JsonResponse: A JSON response indicating the login status.
    """

    if req.method == 'POST':
        username = req.POST.get('username')
        password = req.POST.get('password')
        if not all([username, password]):
            return JsonResponse({
                'status': 'error',
                'message': 'Please insert all the required fields'
            })
        try:
            user = CustomUser.objects.get(username=username, is_superuser=False)
            req.session['logged_in_user_id'] = user.id
            req.session['user_name'] = username
            req.session['user_role'] = user.roles
        except ObjectDoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid username or password'
            })
        if check_password(password, user.password):
            return JsonResponse({
                'status': 'success',
                'redirect_url': '/index'
            })
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid username or password'
        })
    return render(req, 'pages/onboard/login.html')


@csrf_exempt
def admin_login(req):
    if req.method == 'POST':
        username = req.POST.get('username')
        password = req.POST.get('password')
        if not all([username, password]):
            return JsonResponse({
                'status': 'error',
                'message': 'Please insert all the required fields'
            })
        try:
            user = User.objects.get(username=username, is_superuser=True)
            req.session['logged_in_user_id'] = user.id
            req.session['user_name'] = username
            req.session['user_role'] = 'superAdmin'
        except ObjectDoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid username or password'
            })
        if check_password(password, user.password):
            return JsonResponse({
                'status': 'success',
                'redirect_url': '/admin_index/'
            })
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid username or password'
        })
    return render(req, 'pages/superadmin/adminlogin.html')


def forgot_password(req):
    """
    Handle the forgot password process.
    This function processes a POST request containing a username and project code,
    verifies their presence,checks if the provided combination exists in the database,
    and sets a session variable for password reset.

    Parameters:
    - request (HttpRequest): The HTTP request object containing forgot password data.

    Returns:
    - JsonResponse or HttpResponse: A JSON response or an HTML response indicating
    the status of the forgot password
    process.
      - If successful, the response includes a success status, an empty message,
       and a redirect URL to the password
      recovery page.
      - If unsuccessful (e.g., missing fields, invalid username or project code),
      the response includes
       an error status
        and an appropriate error message.

    Example:
    Suppose the user submits a forgot password form with a valid username and project code.
    The function processes the request, sets a session variable for password reset,
    and returns a JSON response:
    {
        'status': 'success',
        'message': '',
        'redirect_url': 'recover-password'
    }
    """
    if req.method == 'POST':
        email = req.POST.get('email')
        if not all([email]):
            return JsonResponse({
                'status': 'error',
                'message': 'Please insert all the required fields'
            })
        try:
            user = CustomUser.objects.filter(email=email).first()
            if user:
                req.session['pass_reset_user_id'] = user.id
                return JsonResponse({
                    'status': 'success',
                    'message': '',
                    'redirect_url': 'recover-password'
                })
            return JsonResponse({
                'status': 'error',
                'message': 'user with this email does not exists.'
            })
        except ObjectDoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Oops, Something went wrong, Please try again later.'
            })
    return render(req, 'pages/onboard/forgot-password.html')


def recover_password(req):
    """
       Handle the password recovery process.

       This function processes a POST request containing new password
       information, verifies the provided passwords,
       and updates the user's password securely using Django's set_password method.

       Parameters:
       - request (HttpRequest): The HTTP request object containing password recovery data.

       Returns:
       - JsonResponse: A JSON response indicating the status of the password recovery process.
         - If successful, the response includes a success status, a success message,
          and a redirect URL.
         - If unsuccessful (e.g., invalid user or session data, password mismatch),
         the response includes an error
          status
           and an appropriate error message.

       Example:
       Suppose the user submits a password recovery form with matching passwords.
       The function processes the request, updates the user's password, and
       returns a JSON response:
       {
           'status': 'success',
           'message': 'Password changed successfully. Please log in to continue',
           'redirect_url': '/'
       }
    """
    if req.method == 'POST':
        password = req.POST.get('password')
        confirm_password = req.POST.get('confirm_password')

        if not all([password, confirm_password]):
            return JsonResponse({
                'status': 'error',
                'message': 'Please insert all the required fields'
            })

        try:
            user_id = req.session.get('pass_reset_user_id')
            user = CustomUser.objects.get(id=user_id)
            if confirm_password == password:
                user.set_password(confirm_password)
                user.save()
                return JsonResponse(
                    {'status': 'success',
                     'message': 'Password changed successfully. Please login to continue',
                     'redirect_url': '/'
                     })

            return JsonResponse({
                'status': 'error',
                'message': "Passwords don't match"
            })
        except ObjectDoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid user or session data.'
            })

    return render(req, 'pages/onboard/recover-password.html')


@request.validator
def index(req):
    """
    Renders the 'index.html' template with user-specific project information.

    Args:
        req (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: Rendered response containing user-specific project data.

    Example:
        The function fetches user-related data such as total projects, completed
        projects, and in-progress projects, and renders the 'index.html' template
        with the fetched information.

    Note:
        This function assumes the presence of a 'user_id' key in the session to
        identify the logged-in user.
    """
    context = {}
    if 'logged_in_user_id' in req.session:
        user_id = req.session.get('logged_in_user_id')
        context = get_user_project_data(user_id)
    return render(req, 'index.html', context)


@csrf_exempt
def admin_index(req):
    context = {}
    user_id = User.objects.filter(is_superuser=True)
    total = Project.objects.all()
    completed_projects = total.filter(status='Completed')
    in_progress_projects = total.filter(status='In Progress')
    context.update({
        'user': user_id,
        'total': total,
        'completed_projects': completed_projects,
        'in_progress_projects': in_progress_projects,
    })
    return render(req, 'pages/superadmin/admin_index.html', context)


@csrf_exempt
def admin_completed_projects(request):
    """
        This Function is filtering out the completed projects
        which are associated to the logged in user.
    """
    projects = Project.objects.filter(status='Completed')
    context = {'project_obj': projects}
    return render(request, 'pages/superadmin/admin_project_listing.html', context)


@csrf_exempt
def admin_in_progress_projects(request):
    """
        This Function is filtering out the completed projects
        which are associated to the logged in user.
    """
    projects = Project.objects.filter(status='In Progress')
    context = {'project_obj': projects}
    return render(request, 'pages/superadmin/admin_project_listing.html', context)


def get_user_project_data(user_id):
    """
    Fetches user-related project data.

    Args:
        user_id (int): The ID of the logged-in user.

    Returns:
        dict: Dictionary containing user-related project information.
    """
    user_qs = CustomUser.objects.filter(id=user_id).first()
    if user_qs.roles == 'client':
        client_projects = ClientProjectAssociation.objects.filter(client=user_qs).values_list('projects', flat=True)
        total = Project.objects.filter(id__in=client_projects)
        completed_projects = total.filter(status__exact='Completed')
        in_progress_projects = total.filter(status__exact='In Progress')
    elif user_qs.roles == 'project_manager':
        manager_projects = UserProjectAssociation.objects.filter(user=user_qs).values_list('projects', flat=True)
        total = Project.objects.filter(id__in=manager_projects).distinct()
        completed_projects = total.filter(status__exact='Completed')
        in_progress_projects = total.filter(status__exact='In Progress')
    else:
        kam_projects = KeyAccountManagerProjectAssociation.objects.filter(key_account_manager=user_qs).values_list(
            'projects', flat=True)
        total = Project.objects.filter(id__in=kam_projects).distinct()
        completed_projects = total.filter(status__exact='Completed')
        in_progress_projects = total.filter(status__exact='In Progress')
    return {
        'user': user_qs,
        'total': total,
        'completed_projects': completed_projects,
        'in_progress_projects': in_progress_projects,
    }


@request.validator
def project_list(req, chart_type):
    """

    """
    user_id = req.session.get('logged_in_user_id')
    user_qs = get_object_or_404(CustomUser, id=user_id)
    if user_qs.roles == 'client':
        projects = Project.objects.filter(clientprojectassociation__client=user_qs).distinct()
    elif user_qs.roles == 'project_manager':
        projects = Project.objects.filter(userprojectassociation__user=user_qs).distinct()
    elif user_qs.roles == 'key_account_holder':
        projects = Project.objects.filter(keyaccountmanagerprojectassociation__key_account_manager=user_qs).distinct()
    context = {'projects_data': projects, 'user_qs': user_qs, 'chart_type': chart_type}
    return render(req, 'pages/projects/project_listing.html', context)


def delete_project(request):
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        user_id = request.session.get('logged_in_user_id')
        try:
            user_qs = get_object_or_404(CustomUser, id=user_id)
            user_associations = {}
            if user_qs.roles == 'client':
                user_associations = ClientProjectAssociation.objects.filter(client_id=user_id)
            elif user_qs.roles == 'project_manager':
                user_associations = UserProjectAssociation.objects.filter(user_id=user_id)
            elif user_qs.roles == 'key_account_holder':
                user_associations = KeyAccountManagerProjectAssociation.objects.filter(key_account_manager_id=user_id)
            project_to_deallocate = Project.objects.get(id=project_id)
            for user_association in user_associations:
                user_association.projects.remove(project_to_deallocate)
            return JsonResponse({'status': 'success'})
        except UserProjectAssociation.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User association not found'})
        except Project.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


@csrf_exempt
def delete_project_by_admin(request):
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        try:
            Project.objects.filter(id=project_id).delete()
            return JsonResponse({'status': 'success'})
        except UserProjectAssociation.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User association not found'})
        except Project.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


@csrf_exempt
def edit_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    context = {'project': project}
    if request.method == 'POST':
        project_name = request.POST.get('projectName')
        projectDescription = request.POST.get('projectDescription')
        projectCode = request.POST.get('projectCode')
        projectScope = request.POST.get('projectScope')
        projectStatus = request.POST.get('projectStatus')
        valid_statuses = dict(Project.STATUS_CHOICES)
        if projectStatus not in valid_statuses:
            pass
        update_query = Project.objects.filter(id=project_id).update(
            code=projectCode,
            name=project_name,
            description=projectDescription,
            scope=projectScope,
            status=projectStatus
        )
        return redirect('edit_project', project_id=project_id)
    return render(request, 'pages/projects/project_edit.html', context)


@request.validator
def completed_project_list(req):
    """
        This Function is filtering out the completed projects
        which are associated to the logged in user.
    """
    user_id = req.session.get('logged_in_user_id')
    user_qs = get_object_or_404(CustomUser, id=user_id)
    projects = Project.objects.filter(status='Completed')
    if user_qs.roles == 'client':
        projects = projects.filter(clientprojectassociation__client=user_qs)
    elif user_qs.roles == 'project_manager':
        projects = projects.filter(userprojectassociation__user=user_qs)
    elif user_qs.roles == 'key_account_holder':
        projects = projects.filter(keyaccountmanagerprojectassociation__key_account_manager=user_qs)
    context = {'projects_data': projects, 'user_qs': user_qs}
    return render(req, 'pages/projects/project_listing.html', context)


@request.validator
def in_progress_project_list(req):
    """
    Renders the 'project_listing.html' template with a list of projects associated
    with the logged-in user.

    Args:
        req (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: Rendered response containing the project listing for the user.

    Example:
        The function fetches the logged-in user's ID from the session, retrieves the user object,
        and queries for projects associated with the user. The project data is then passed to the
        'project_listing.html' template for rendering.

    Note:
        This function assumes the presence of a 'user_id' key in the session to
        identify the logged-in user.

    """
    user_id = req.session.get('logged_in_user_id')
    user_qs = get_object_or_404(CustomUser, id=user_id)
    projects = Project.objects.filter(status='In Progress')
    if user_qs.roles == 'client':
        projects = projects.filter(clientprojectassociation__client=user_qs)
    elif user_qs.roles == 'project_manager':
        projects = projects.filter(userprojectassociation__user=user_qs)
    elif user_qs.roles == 'key_account_holder':
        projects = projects.filter(keyaccountmanagerprojectassociation__key_account_manager=user_qs)
    context = {'projects_data': projects, 'user_qs': user_qs}
    return render(req, 'pages/projects/project_listing.html', context)


def calculate_luminance(color):
    if isinstance(color, int):
        color = (color, color, color)
    if color is not None:
        r, g, b = color
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
        return luminance
    else:
        return 0.5


def extract_assignee_partners(req, code):
    assignee_partner_dict = {}
    user = req.session.get('logged_in_user_id')
    for patent_data in PatentData.objects.filter(project_code=code):
        assignee_partners_str = patent_data.assignee_standardized
        assignee, *partners = map(lambda x: x.strip().title(), assignee_partners_str.split('|'))
        if assignee in assignee_partner_dict:
            assignee_partner_dict[assignee].extend(p for p in partners if p)
        else:
            assignee_partner_dict[assignee] = [p for p in partners if p]
    return assignee_partner_dict


def get_top_assignees_by_year(req, code):
    top_assignees = PatentData.objects.filter(project_code=code).values('assignee_standardized').annotate(
        count=Count('assignee_standardized')).order_by('-count')[:10]
    data = {}

    for assignee in top_assignees:
        assignee_name = assignee['assignee_standardized']
        year_counts = PatentData.objects.filter(project_code=code, assignee_standardized=assignee_name).values(
            year=ExtractYear('application_dates')).annotate(count=Count('id')).order_by('year')

        for year_count in year_counts:
            year = year_count['year']
            count = year_count['count']

            if year not in data:
                data[year] = {}
            data[year][assignee_name] = count

    sorted_data = {}
    for year in sorted(data.keys()):
        sorted_data[year] = data[year]
    return sorted_data


@csrf_exempt
def create_chart_heading(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            chart_id = data.get('chart_id')
            new_heading = data.get('new_heading')
            project_id = data.get('project_id')
            project_instance = Project.objects.get(id=project_id)
            chart_heading = ChartHeading.objects.filter(chart_source_id=chart_id, project=project_instance).first()

            if chart_heading:
                chart_heading.heading = new_heading
                chart_heading.save()
            else:
                ChartHeading.objects.create(chart_source_id=chart_id, project=project_instance, heading=new_heading)
            return JsonResponse({'success': True})
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
        except Exception as e:
            print("Exception:", str(e))
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False, 'error': 'Invalid request'})


@request.validator
def tech_charts(req, project_id):
    """
    Logic for tech charts
    """
    user_qs = get_object_or_404(CustomUser, id=req.session.get('logged_in_user_id'))
    project = get_object_or_404(Project, id=project_id)
    if not (
            UserProjectAssociation.objects.filter(user=user_qs, projects=project).exists() or
            ClientProjectAssociation.objects.filter(client=user_qs, projects=project).exists() or
            KeyAccountManagerProjectAssociation.objects.filter(key_account_manager=user_qs, projects=project).exists()
    ):
        return HttpResponse("You are not authorized to view data for this project.")

    proj_obj = Project.objects.filter(id=project_id).first()
    proj_name = proj_obj.name
    context = {'project_id': project_id, 'proj_name': proj_name}

    def get_chart_heading(project_id, chart_source_id):
        try:
            project_inst = Project.objects.get(id=project_id)
            heading_obj = ChartHeading.objects.filter(project=project_inst, chart_source_id=chart_source_id).first()
            return heading_obj.heading if heading_obj else 'XYZ'
        except Project.DoesNotExist:
            return 'XYZ'

    context['chart_heading1'] = get_chart_heading(project_id, 1)
    context['chart_heading2'] = get_chart_heading(project_id, 2)
    context['chart_heading3'] = get_chart_heading(project_id, 3)
    context['chart_heading4'] = get_chart_heading(project_id, 4)

    if Category.objects.filter(project_id=proj_obj.id).exists():
        num_header_levels = Category.objects.filter(project_id=proj_obj.id).first().num_header_levels
        level = num_header_levels - 1
        heat_data = get_heatmap_data(req, level, proj_obj.id)
        others_count = get_others_split_count(req, num_header_levels, proj_obj.id)
        others_category_count = json.dumps(others_category_wise_count(req, num_header_levels, proj_obj.id))
        all_col_count = json.dumps(get_col_tick_count(req, num_header_levels, proj_obj.id))
        all_child_categories_count = json.dumps(barchart_tick_count(req, num_header_levels, proj_obj.id))

        context.update({
            'others_count': json.dumps(others_count),
            'get_all_data': all_col_count,
            'others_category_count': others_category_count,
            "all_child_categories_count": all_child_categories_count,
            'heatmap': heat_data
        })

    if req.method == 'POST':
        num_header_levels = int(req.POST.get('level'))
        uploaded_media = req.FILES.get('technical_excel')
        if uploaded_media:
            df = pd.read_excel(uploaded_media, header=list(range(num_header_levels)))
            save_to_categories(df, num_header_levels, proj_obj)
            level = num_header_levels - 1
            heat_data = get_heatmap_data(req, level, proj_obj.id)
            others_count = get_others_split_count(req, num_header_levels, proj_obj.id)
            others_category_count = json.dumps(others_category_wise_count(req, num_header_levels, proj_obj.id))
            all_col_count = json.dumps(get_col_tick_count(req, num_header_levels, proj_obj.id))
            all_child_categories_count = json.dumps(barchart_tick_count(req, num_header_levels, proj_obj.id))

            context.update({
                'others_count': json.dumps(others_count),
                'get_all_data': all_col_count,
                'others_category_count': others_category_count,
                'all_child_categories_count': all_child_categories_count,
                'heatmap': heat_data
            })

    return render(req, 'pages/charts/technical_chart.html', context)


@transaction.atomic
def save_to_categories(df, num_header_levels, proj_obj):
    if Category.objects.filter(project_id=proj_obj.id).exists():
        Category.objects.filter(project_id=proj_obj.id).delete()
    parent_stack = []
    for col_idx, column in enumerate(df.columns):
        current_level = 0
        for header_level in range(num_header_levels):
            category_name = column[header_level]
            if current_level > 0:
                parent_category = parent_stack[-1]
            else:
                parent_category = None
            category, created = Category.objects.get_or_create(name=category_name, parent=parent_category,
                                                               level=header_level, project_id=proj_obj,
                                                               num_header_levels=num_header_levels)
            parent_stack.append(category)
            current_level += 1
        child_category = category
        parent_category = parent_stack.pop()
        child_column_name = column[num_header_levels - 1]
        values = df[column].tolist()[1:]
        values = [None if pd.isna(value) else value for value in values]
        if child_category.value:
            child_category.value[child_column_name] = values
        else:
            child_category.value = {child_column_name: values}
        child_category.save()
        parent_stack = []


# =============================hierarchical charts ============================
def process_category(category, children_list, proj_id):
    existing_category = next((child for child in children_list if child["name"] == category.name), None)
    if existing_category:
        if category.value:
            for key, values_list in category.value.items():
                count_p = sum(1 for value in values_list if value == 'P')
                existing_category["value"] = count_p if count_p > 0 else existing_category.get("value", None)
        children = Category.objects.filter(parent=category, project_id=proj_id)
        for child in children:
            process_category(child, existing_category.setdefault("children", []), proj_id)
    else:
        category_data = {"name": category.name, "children": []}
        if category.value:
            for key, values_list in category.value.items():
                count_p = sum(1 for value in values_list if value == 'P')
                category_data["value"] = count_p if count_p > 0 else category_data.get("value", None)
        children = Category.objects.filter(parent=category, project_id=proj_id)
        for child in children:
            process_category(child, category_data.setdefault("children", []), proj_id)
        children_list.append(category_data)


def get_col_tick_count(request, num_header_levels, proj_id):
    data = {"name": "", "children": []}
    root_categories = Category.objects.filter(parent__isnull=True, project_id=proj_id)
    for root_category in root_categories:
        process_category(root_category, data["children"], proj_id=proj_id)
    return data


# ===========================data view and download==============
# ===========================other col split count==============

def process_top_ten_assignees(req, project_code):
    data = PatentData.objects.filter(project_code=project_code).exclude(
        assignee_standardized__isnull=True
    ).values('assignee_standardized').annotate(
        count=Count('assignee_standardized')
    ).order_by('-count')[:10]
    result = []
    for item in data:
        assignee = item['assignee_standardized']
        count = item['count']
        publication_numbers = list(PatentData.objects.filter(
            project_code=project_code,
            assignee_standardized=assignee
        ).values_list('publication_number', flat=True))
        result.append({
            'Assignee - Standardized': assignee,
            'publication_numbers': publication_numbers
        })
    return result


def get_heatmap_data(request, level, project_id):
    project = Project.objects.get(id=project_id)
    code = project.code
    context = {}
    output = []
    top_ten_assignee = process_top_ten_assignees(request, code)
    all_assignee_publication_numbers = []
    assignee_outputs = {}
    assignee_publication_map = {assignee['Assignee - Standardized']: assignee.get('publication_numbers', []) for
                                assignee in top_ten_assignee}
    if top_ten_assignee:
        for assignee in top_ten_assignee:
            assignee_name = assignee['Assignee - Standardized']
            assignee_publication_numbers = assignee_publication_map[assignee_name]
            all_assignee_publication_numbers.extend(assignee_publication_numbers)
            assignee_outputs[assignee_name] = {}
    try:
        all_child = Category.objects.filter(level=level, project_id=project_id).exclude(name='Publication Number')
        child_cat_names = [cat.name for cat in all_child]
        values = Category.objects.filter(level=level, project_id=project_id).values_list('value', flat=True)
        for category in values:
            category_name = list(category.keys())[0]
            if category_name != 'Publication Number':
                category_data = category[category_name]
                category_counts = {
                    pub_num: 1 if i < len(category_data) and category_data[i] == 'P' else 0
                    for i, pub_num in enumerate(all_assignee_publication_numbers)
                }
                for assignee_name, pub_numbers in assignee_publication_map.items():
                    p_count = sum(category_counts[pub_num] for pub_num in pub_numbers)
                    if assignee_name not in assignee_outputs:
                        assignee_outputs[assignee_name] = {}
                    assignee_outputs[assignee_name][category_name] = p_count
        for assignee_name, assignee_data in assignee_outputs.items():
            assignee_output = {'assignee_name': assignee_name}
            assignee_output.update(assignee_data)
            output.append(assignee_output)
        assignees = list(assignee_outputs.keys())
        categories = child_cat_names
        z = []
        for assignee in assignees:
            row = [assignee_outputs[assignee].get(cat, None) for cat in categories]
            z.append(row)
        context.update({
            "top_ten_assignee": assignees,
            "child_cat_names": categories,
            "heatmap_data": {
                "z": z,
                "x": categories,
                "y": assignees
            }
        })
    except ObjectDoesNotExist:
        context = None
    return context


def get_others_split_count(request, num_header_levels, proj_id):
    data = []
    others_child_columns = Category.objects.filter(name__icontains='Other-', level=num_header_levels - 1,
                                                   project_id_id=proj_id)
    if others_child_columns.exists():
        for child_column in others_child_columns:
            parent_category = child_column.parent
            if parent_category:
                category_info = {'category': parent_category.name, 'litres': 0}
                column_value = child_column.value
                if column_value:
                    total_count = 0
                    for key, value in column_value.items():
                        for ele in value:
                            if ele is not None:
                                elements = ele.split('|')
                                count = sum(1 for elem in elements if elem.strip() == 'P')
                                total_count += count
                    category_info['litres'] = total_count
                data.append(category_info)
    else:
        print("No child columns named 'Others' found.")
    return data


# ===========================other column split count category wise start==============
def others_category_wise_count(request, num_header_levels, proj_id):
    data = []
    others_child_columns = Category.objects.filter(name__icontains='Other-', level=num_header_levels - 1,
                                                   project_id=proj_id)
    if others_child_columns.exists():
        for child_column in others_child_columns:
            column_value = child_column.value
            if column_value:
                total_count = 0
                unique_elements = set()
                for key, value in column_value.items():
                    for ele in value:
                        if ele is not None:
                            elements = ele.split('|')
                            count = sum(1 for elem in elements if elem.strip() == 'P')
                            total_count += count
                non_none_count = total_count
                data.append({"child_cat_name": child_column.name, "litres": total_count})
            else:
                data.append({"child_cat_name": child_column.name, "litres": 0})
    else:
        print("No child columns named 'Others' found.")
    return data


# =========================== other column split count category wise end==============
def barchart_tick_count(request, num_header_levels, proj_id):
    ignore_keys = ['Publication Number', 'Other-']
    child_categories = {}

    def process_category(category):
        if category.value is not None:
            for key, values_list in category.value.items():
                if key not in ignore_keys and not any(ignore_key in key for ignore_key in ignore_keys):
                    count_p = sum(1 for value in values_list if value == 'P')
                    child_categories[key] = count_p
        children = Category.objects.filter(parent=category, project_id=proj_id)
        for child in children:
            process_category(child)

    root_categories = Category.objects.filter(parent__isnull=True, project_id=proj_id)
    for root_category in root_categories:
        process_category(root_category)

    for category in Category.objects.filter(level__gt=0, level__lt=num_header_levels, project_id=proj_id):
        process_category(category)
    return child_categories


# ===================================================================
@csrf_exempt
def get_q_object(assignee, partner):
    return Q(assignee_standardized__icontains=assignee) & Q(assignee_standardized__icontains=partner)


@csrf_exempt
def competitor_colab_view(request, proj_code):
    code = Project.objects.filter(code=proj_code).first().code
    try:
        if request.method == 'POST':
            if 'patent_data' in request.session:
                del request.session['patent_data']
            if 'partner_app_date_qs' in request.session:
                del request.session['partner_app_date_qs']
            if 'ass_pub_date_qs' in request.session:
                del request.session['ass_pub_date_qs']
            if 'ass_legal_status_qs' in request.session:
                del request.session['ass_legal_status_qs']
            if 'top_ten_highest_citing_qs' in request.session:
                del request.session['top_ten_highest_citing_qs']
            data = json.loads(request.body)
            if data.get('assignee_standardized') and data.get('legal_status') and data.get('type'):
                assignee_list = [data.get('assignee_standardized')]
                lega_status = PatentData.objects.filter(assignee_standardized__in=assignee_list,
                                                        legal_status=data.get('legal_status'), project_code=code)

                if data.get('type') == 'display':
                    ass_legal_status_qs = serialize('json', lega_status)
                    context = {'ass_legal_status_qs': json.loads(ass_legal_status_qs)}
                    request.session['ass_legal_status_qs'] = json.loads(ass_legal_status_qs)
                    return JsonResponse(
                        {'success': True, 'data': context,
                         'redirect_url': reverse('competitor_colab_view', kwargs={'proj_code': proj_code}),
                         'type': 'display'})
                data_list = []
                if data.get('type') == 'file':
                    for patent_data in lega_status:
                        data = {
                            'Publication Number': patent_data.publication_number,
                            'Assignee': patent_data.assignee_standardized,
                            'Legal Status': patent_data.legal_status,
                            'Cited Patents Count': patent_data.cited_patents_count,
                            'Citing Patents Count': patent_data.citing_patents_count,
                            'Inventors': patent_data.inventors,
                            'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                            'Application Date': patent_data.application_dates,
                            'Publication Date': patent_data.publication_dates,
                            'Application Number': patent_data.application_number,
                            'CPC': patent_data.cpc,
                            'IPC': patent_data.ipc,
                            'E-Fan': patent_data.e_fan,
                        }
                        data_list.append(data)
                    df = pd.DataFrame(data_list)
                    response = HttpResponse(
                        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                    response['Content-Disposition'] = 'attachment; filename=Assignee_Partner.xlsx'
                    df.to_excel(response, index=False)
                    return response
            elif data.get('assignee') and data.get('publication'):
                year_wise_count = PatentData.objects.filter(assignee_standardized__icontains=data.get('assignee'),
                                                            publication_number=data.get('publication'),
                                                            project_code=code,
                                                            )
                if data.get('type') == 'display':
                    ass_pub_date_qs = serialize('json', year_wise_count)
                    context = {'ass_pub_date_qs': json.loads(ass_pub_date_qs)}
                    request.session['ass_pub_date_qs'] = json.loads(ass_pub_date_qs)
                    return JsonResponse(
                        {'success': True, 'data': context,
                         'redirect_url': reverse('competitor_colab_view', kwargs={'proj_code': proj_code}),
                         'type': 'display'})

                data_list = []
                if data.get('type') == 'file':
                    for patent_data in year_wise_count:
                        data = {
                            'Publication Number': patent_data.publication_number,
                            'Assignee': patent_data.assignee_standardized,
                            'Legal Status': patent_data.legal_status,
                            'Cited Patents Count': patent_data.cited_patents_count,
                            'Citing Patents Count': patent_data.citing_patents_count,
                            'Inventors': patent_data.inventors,
                            'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                            'Application Date': patent_data.application_dates,
                            'Publication Date': patent_data.publication_dates,
                            'Application Number': patent_data.application_number,
                            'CPC': patent_data.cpc,
                            'IPC': patent_data.ipc,
                            'E-Fan': patent_data.e_fan,
                        }
                        data_list.append(data)
                    df = pd.DataFrame(data_list)
                    response = HttpResponse(
                        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                    response['Content-Disposition'] = 'attachment; filename=Assignee_Partner.xlsx'
                    df.to_excel(response, index=False)
                    return response

            elif data.get('assignee') and data.get('year'):
                year_wise_count = PatentData.objects.filter(assignee_standardized__icontains=data.get('assignee'),
                                                            application_dates__year=data.get('year'),
                                                            project_code=code,
                                                            )
                if data.get('type') == 'display':
                    partner_app_date_qs = serialize('json', year_wise_count)
                    context = {'partner_app_date_qs': json.loads(partner_app_date_qs)}
                    request.session['partner_app_date_qs'] = json.loads(partner_app_date_qs)
                    return JsonResponse(
                        {'success': True, 'data': context,
                         'redirect_url': reverse('competitor_colab_view', kwargs={'proj_code': proj_code}),
                         'type': 'display'})

                data_list = []
                if data.get('type') == 'file':
                    for patent_data in year_wise_count:
                        data = {
                            'Publication Number': patent_data.publication_number,
                            'Assignee': patent_data.assignee_standardized,
                            'Legal Status': patent_data.legal_status,
                            'Cited Patents Count': patent_data.cited_patents_count,
                            'Citing Patents Count': patent_data.citing_patents_count,
                            'Inventors': patent_data.inventors,
                            'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                            'Application Date': patent_data.application_dates,
                            'Publication Date': patent_data.publication_dates,
                            'Application Number': patent_data.application_number,
                            'CPC': patent_data.cpc,
                            'IPC': patent_data.ipc,
                            'E-Fan': patent_data.e_fan,
                        }
                        data_list.append(data)
                    df = pd.DataFrame(data_list)
                    response = HttpResponse(
                        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                    response['Content-Disposition'] = 'attachment; filename=Assignee_Partner.xlsx'
                    df.to_excel(response, index=False)
                    return response
            elif data.get('type') == 'allCitedDisplay':
                filtered_data = PatentData.objects.filter(citing_patents_count__isnull=False,
                                                          project_code=code)
                top_ten_highest_citing = filtered_data.order_by('-citing_patents_count')[:10]
                top_ten_highest_citing_qs = serialize('json', top_ten_highest_citing)
                context = {'top_ten_highest_citing_qs': json.loads(top_ten_highest_citing_qs)}
                request.session['top_ten_highest_citing_qs'] = json.loads(top_ten_highest_citing_qs)
                return JsonResponse(
                    {'success': True, 'data': context,
                     'redirect_url': reverse('competitor_colab_view', kwargs={'proj_code': proj_code}),
                     'type': 'display'})

            elif data.get('type') == 'allCitedFile':
                filtered_data = PatentData.objects.filter(citing_patents_count__isnull=False,
                                                          project_code=code)
                top_ten_highest_citing = filtered_data.order_by('-citing_patents_count')[:10]
                data_list = []
                for patent_data in top_ten_highest_citing:
                    data = {
                        'Publication Number': patent_data.publication_number,
                        'Assignee': patent_data.assignee_standardized,
                        'Legal Status': patent_data.legal_status,
                        'Cited Patents Count': patent_data.cited_patents_count,
                        'Citing Patents Count': patent_data.citing_patents_count,
                        'Inventors': patent_data.inventors,
                        'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                        'Application Date': patent_data.application_dates,
                        'Publication Date': patent_data.publication_dates,
                        'Application Number': patent_data.application_number,
                        'CPC': patent_data.cpc,
                        'IPC': patent_data.ipc,
                        'E-Fan': patent_data.e_fan,
                    }
                    data_list.append(data)
                df = pd.DataFrame(data_list)
                response = HttpResponse(
                    content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                response['Content-Disposition'] = 'attachment; filename=Assignee_Partner.xlsx'
                df.to_excel(response, index=False)
                return response

            elif data.get('assignee') and data.get('partners'):
                assignee = data.get('assignee')
                partners_encoded = data.get('partners')
                partners_decoded = unquote(partners_encoded)
                partners_dict = json.loads(partners_decoded)
                partners_list = list(partners_dict)
                patent_data = {}

                if data.get('type') == 'display':
                    for partner in partners_list:
                        q_obj = get_q_object(assignee, partner)
                        patents = PatentData.objects.filter(q_obj, project_code=code)
                        patents_data = serialize('json', patents)
                        patents_list = json.loads(patents_data)
                        patent_data[f"{assignee}_{partner}"] = patents_list
                    context = {'patent_data': patent_data}
                    request.session['patent_data'] = patent_data
                    return JsonResponse(
                        {'success': True, 'data': context,
                         'redirect_url': reverse('competitor_colab_view', kwargs={'proj_code': proj_code}),
                         'type': 'display'})

                data_list = []
                if data.get('type') == 'file':
                    for partner in partners_list:
                        q_obj = get_q_object(assignee, partner)
                        patents = PatentData.objects.filter(q_obj, project_code=code)
                        for patent_data in patents:
                            data = {
                                'Publication Number': patent_data.publication_number,
                                'Assignee': patent_data.assignee_standardized,
                                'Legal Status': patent_data.legal_status,
                                'Cited Patents Count': patent_data.cited_patents_count,
                                'Citing Patents Count': patent_data.citing_patents_count,
                                'Inventors': patent_data.inventors,
                                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                                'Application Date': patent_data.application_dates,
                                'Publication Date': patent_data.publication_dates,
                                'Application Number': patent_data.application_number,
                                'CPC': patent_data.cpc,
                                'IPC': patent_data.ipc,
                                'E-Fan': patent_data.e_fan,
                            }
                            data_list.append(data)
                        df = pd.DataFrame(data_list)
                        response = HttpResponse(
                            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                        response['Content-Disposition'] = 'attachment; filename=Assignee_Partner.xlsx'
                        df.to_excel(response, index=False)
                        return response

        else:
            if request.session.get('patent_data'):
                context = request.session.get('patent_data', {})
                return render(request, 'pages/charts/competitor_data_view.html', {'patent_data': context})
            elif request.session.get('partner_app_date_qs'):
                context = request.session.get('partner_app_date_qs', {})
                return render(request, 'pages/charts/competitor_data_view.html', {'partner_app_date_qs': context})
            elif request.session.get('ass_pub_date_qs'):
                context = request.session.get('ass_pub_date_qs', {})
                return render(request, 'pages/charts/competitor_data_view.html', {'ass_pub_date_qs': context})
            elif request.session.get('ass_legal_status_qs'):
                context = request.session.get('ass_legal_status_qs', {})
                return render(request, 'pages/charts/competitor_data_view.html', {'ass_legal_status_qs': context})

            elif request.session.get('top_ten_highest_citing_qs'):
                context = request.session.get('top_ten_highest_citing_qs', {})
                return render(request, 'pages/charts/competitor_data_view.html', {'top_ten_highest_citing_qs': context})

            # elif request.session.get('partner_ass_date_qs'):
            #     context = request.session.get('partner_ass_date_qs', {})
            #     return render(request, 'pages/charts/competitor_data_view.html', {'partner_ass_date_qs': context})
    except Exception as e:
        print(f"Error in competitor_colab_view: {e}")
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


# ===========================data view and download==============

@request.validator
def competitor_charts(req, project_id):
    user_id = req.session.get('logged_in_user_id')
    user_qs = get_object_or_404(CustomUser, id=user_id)
    project = get_object_or_404(Project, id=project_id)
    if not (
            UserProjectAssociation.objects.filter(user=user_qs, projects=project).exists() or
            ClientProjectAssociation.objects.filter(client=user_qs, projects=project).exists() or
            KeyAccountManagerProjectAssociation.objects.filter(key_account_manager=user_qs, projects=project).exists()
    ):
        return HttpResponse("You are not authorized to view competitor charts for this project.")
    project_id_template = project.id
    code = project.code
    project_name = project.name
    data = PatentData.objects.filter(project_code=code)
    data1 = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    result = []
    for item in data1:
        assignee_name = item['assignee_standardized']
        partners_list = extract_assignee_partners(req, code).get(assignee_name.title(), [])
        partner_count_dict = dict(Counter(partners_list))
        result.append({
            'assignee': assignee_name,
            'partners': partner_count_dict,
            'partner_count': sum(partner_count_dict.values())
        })
    res = result
    req.session['res'] = res
    assignees = [entry['assignee'].title() for entry in result]
    partners = sorted(set(partner for entry in result for partner in entry['partners']))
    partner_count_matrix = [
        [entry['partners'].get(partner, None) for partner in partners] for entry in result
    ]
    text_colors = [['dark' if calculate_luminance(color) < 0.5 else 'light' for color in row] for row in
                   partner_count_matrix]
    if not partners:
        fig1 = go.Figure()
        fig1.add_annotation(
            text="No partner data found",
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=20)
        )
    else:
        truncated_assignees = [assignee[:25] + '...' if len(assignee) > 30 else assignee for assignee in assignees]
        truncated_partners = [partner[:25] + '...' if len(partner) > 30 else partner for partner in partners]
        fig1 = go.Figure(data=go.Heatmap(
            z=partner_count_matrix,
            x=truncated_partners,
            y=truncated_assignees,
            hoverinfo='none',
            colorscale='PuBuGn',
            colorbar=dict(title='Partner Count'),
            text=[
                [f'<span style="color:{text_colors[i][j]}">{count}</span>' if count is not None else '' for j, count in
                 enumerate(row)] for i, row in enumerate(partner_count_matrix)
            ],
            texttemplate="%{text}",
            textfont={"size": 14}
        ))
    fig1.update_layout(
        title='Collaborations of competitors',
        xaxis=dict(title='Partners'),
        yaxis=dict(title='Assignees'),
        height=500,
        width=995,
    )
    div1 = fig1.to_html()
    # ==================================BUBBLE===================================================
    result_b = get_top_assignees_by_year(req, code)
    div2 = ''
    if result_b:
        data = []
        for year, assignee_dict in sorted(result_b.items()):
            for assignee, count in assignee_dict.items():
                data.append({'Assignee': assignee.title(), 'Year': year, 'Count': count})
        df = pd.DataFrame(data)
        fig2 = px.scatter(
            df,
            x="Year",
            y="Assignee",
            size="Count",
            size_max=20,
            height=500,
            width=995,
        )
        fig2.update_layout(
            title='Overall patent filing',
            xaxis_title='Application Year',
            yaxis_title='Assignee'
        )
        fig2.update_xaxes(type='category')
        fig2.update_traces(marker=dict(line=dict(width=0.5, color='DarkSlateGray')))
        div2 = fig2.to_html(full_html=False)
    # ===================================BAR CHART=========================================
    filtered_data = PatentData.objects.filter(citing_patents_count__isnull=False, project_code=code)
    top_ten_highest_citing = filtered_data.order_by('-citing_patents_count')[:10]
    top_ten_values = [val.citing_patents_count for val in top_ten_highest_citing]
    assignee_names = [val.assignee_standardized.split('|')[0] for val in top_ten_highest_citing]
    publication_numbers = [val.publication_number for val in top_ten_highest_citing]
    cited_values = [val.cited_patents_count if val.cited_patents_count is not None else 1 for val in
                    top_ten_highest_citing]
    citation_index_values = [round(citing / cited, 2) if cited != 0 else 0 for citing, cited in
                             zip(top_ten_values, cited_values)]

    y_labels = [f"{assignee} | {publication}" for assignee, publication in zip(assignee_names, publication_numbers)]
    table_data = []

    for val in top_ten_highest_citing:
        assignee_name = val.assignee_standardized.split('|')[0]
        publication_number = val.publication_number
        citing_count = val.citing_patents_count
        cited_count = val.cited_patents_count if val.cited_patents_count is not None else 1
        if cited_count != 0:
            citation_index = round(citing_count / cited_count, 2)
        else:
            citation_index = 0

        row_dict = {
            'assignee': assignee_name,
            'publication_number': publication_number,
            'citing_count': citing_count,
            'citing_index': citation_index
        }
        table_data.append(row_dict)
    fig3 = make_subplots(rows=1, cols=2, shared_yaxes=True, subplot_titles=['Top Citing Patents', 'Citation Index'])
    fig3.add_trace(
        go.Bar(
            x=top_ten_values,
            y=y_labels,
            text=top_ten_values,
            orientation='h',
            marker=dict(color=['aliceblue', 'cadetblue', 'deepskyblue', 'dodgerblue', 'lightblue', 'cornflowerblue',
                               'midnightblue', 'mediumblue', 'blue']),
            name=''
        ),
        row=1, col=1
    )
    fig3.add_trace(
        go.Bar(
            x=citation_index_values,
            y=y_labels,
            text=citation_index_values,
            orientation='h',
            marker=dict(color=['aliceblue', 'cadetblue', 'deepskyblue', 'dodgerblue', 'lightblue', 'cornflowerblue',
                               'midnightblue', 'mediumblue', 'blue']),
            name=''
        ),
        row=1, col=2
    )
    fig3.update_layout(
        title="Influence of Innovation",
        height=400,
        width=995,
        margin=dict(t=50, b=30, r=10, l=10),  # Adjust margins
        showlegend=False  # Remove legend to save space
    )
    fig3.update_layout(updatemenus=[])
    div3 = fig3.to_html(full_html=False)
    # =========================================================================
    top_assignees = PatentData.objects.filter(project_code=code).values(
        'assignee_standardized').annotate(
        count=Count('assignee_standardized')).order_by('-count')[:10]
    top_assignee_ids = [a['assignee_standardized'] for a in top_assignees]
    legal_status_counts = PatentData.objects.filter(assignee_standardized__in=top_assignee_ids,
                                                    project_code=code).values(
        'assignee_standardized', 'legal_status').annotate(count=Count('legal_status')).order_by('assignee_standardized')

    result = {}
    for ls in legal_status_counts:
        assignee = ls['assignee_standardized']
        status = ls['legal_status']
        count = ls['count']
        if assignee not in result:
            result[assignee] = {}
        result[assignee][status] = count
    assignee_names = list(result.keys())
    status_types = list(set(status for status_dict in result.values() for status in status_dict.keys()))

    fig4 = go.Figure()
    for status in status_types:
        status_counts = [assignee_data.get(status, 0) for assignee_data in result.values()]
        fig4.add_trace(go.Bar(x=assignee_names, y=status_counts, name=status,
                              text=status_counts, textposition='auto'))
    fig4.update_layout(
        title='Legal Status Distribution',
        barmode='stack',
        xaxis={'categoryorder': 'total descending'},
        height=600,
        width=990
    )

    div4 = fig4.to_html(full_html=False)
    # ===========================================================================

    # df = px.data.gapminder().query("year==2007")
    # fig6 = px.choropleth(df, locations="iso_alpha",
    #                      color="lifeExp",
    #                      hover_name="country",
    #                      color_continuous_scale=px.colors.sequential.Plasma)

    # Set the height and width of the choropleth map
    # fig6.update_layout(
    #     height=600,
    #     width=995
    # )
    # div6 = fig6.to_html(full_html=False)
    context = {'plot_div1': div1, 'plot_div2': div2, 'plot_div3': div3, 'plot_div4': div4,
               'data1': data1, 'result': res, 'data': data, 'proj_code': code,
               'project_id': project_id_template, 'project_name': project_name,
               'table_data': table_data, 'legal_status_counts': legal_status_counts}
    return render(req, 'pages/charts/competitor_charts.html', context)


def handle_nat(dt):
    if pd.isna(dt):
        return None
    else:
        return dt


def download_publication_exl(request, year, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    innovators = PatentData.objects.filter(publication_dates__year=year, project_code=code)
    if request.GET.get('display'):
        context = {
            'publication_trend': innovators,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in innovators:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=Publication Trend.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Publication Trend')
            workbook = writer.book
            worksheet = writer.sheets['Publication Trend']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def download_exp_exl(request, year, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    exp_qs = PatentData.objects.filter(expected_expiry_dates__year=year, project_code=code)
    for patent_data in exp_qs:
        if request.GET.get('display'):
            context = {
                'exp_qs': exp_qs,
            }
            return render(request, 'pages/charts/top_ten_ipc.html', context)
        else:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Remaining Life': patent_data.remaining_life,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=expected_expiry_date.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='expected_expiry_date')
            workbook = writer.book
            worksheet = writer.sheets['expected_expiry_date']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def download_legal_status_exl(request, status, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    innovators = PatentData.objects.filter(legal_status=status, project_code=code)
    if request.GET.get('display'):
        context = {
            'legal_status_qs': innovators,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in innovators:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=legal_status_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='legal_status_data')
            workbook = writer.book
            worksheet = writer.sheets['legal_status_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)

        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def individual_cpc_exl(request, cpc, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    cpc_qs = PatentData.objects.filter(cpc__startswith=cpc, project_code=code)
    if request.GET.get('display'):
        context = {
            'cpc_qs': cpc_qs,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in cpc_qs:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Remaining Life': patent_data.remaining_life,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=CPC_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='CPC_data')
            workbook = writer.book
            worksheet = writer.sheets['CPC_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def individual_ipc_exl(request, ipc, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    ipc_qs = PatentData.objects.filter(ipc__startswith=ipc, project_code=code)
    if request.GET.get('display'):
        context = {
            'ipc_qs': ipc_qs,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in ipc_qs:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=IPC_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='IPC_data')
            workbook = writer.book
            worksheet = writer.sheets['IPC_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def download_innovative_exl(request, country, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    innovators = PatentData.objects.filter(publication_number__startswith=country, project_code=code)
    if request.GET.get('display'):
        context = {
            'innovators': innovators,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in innovators:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=TOP Innovative.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='top_innovative')
            workbook = writer.book
            worksheet = writer.sheets['top_innovative']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def download_ind_citing_excel(request, patent, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    top_ten_citing_patents = PatentData.objects.filter(
        publication_number=patent, project_code=code
    )
    if request.GET.get('display'):
        context = {
            'ind_citing_patents': top_ten_citing_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in top_ten_citing_patents:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={patent}_citing_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name=f'{patent}_citing_data')
            workbook = writer.book
            worksheet = writer.sheets[f'{patent}_citing_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def download_top_assignee_exl(request, assignee, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    top_ten_assignees = PatentData.objects.filter(
        assignee_standardized=assignee, project_code=code
    )
    if request.GET.get('display'):
        context = {
            'top_ten_assignees_view': top_ten_assignees,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in top_ten_assignees:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={assignee}_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name=f'{assignee}_data')
            workbook = writer.book
            worksheet = writer.sheets[f'{assignee}_data.xlsx']

            # Set the column widths
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)

        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def download_recent_assignee_exl(request, assignee, project_id):
    data_list = []
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    code = Project.objects.filter(id=project_id).first().code
    top_ten_assignees = PatentData.objects.filter(
        assignee_standardized=assignee, project_code=code,
        application_dates__year__gte=last_five_years_start
    )
    if request.GET.get('display'):
        context = {
            'top_recent_assignees_view': top_ten_assignees,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in top_ten_assignees:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=Recent {assignee}_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name=f'Recent {assignee}_data')
            workbook = writer.book
            worksheet = writer.sheets[f'Recent {assignee}_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def download_ind_cited_excel(request, patent, project_id):
    data_list = []
    code = Project.objects.filter(id=project_id).first().code
    top_ten_citing_patents = PatentData.objects.filter(
        publication_number=patent, project_code=code
    )
    if request.GET.get('display'):
        context = {
            'ind_cited_patents': top_ten_citing_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        for patent_data in top_ten_citing_patents:
            data = {
                'Publication Number': patent_data.publication_number,
                'Assignee': patent_data.assignee_standardized,
                'Legal Status': patent_data.legal_status,
                'Cited Patents Count': patent_data.cited_patents_count,
                'Citing Patents Count': patent_data.citing_patents_count,
                'Inventors': patent_data.inventors,
                'Earliest Patent Priority Date': patent_data.earliest_patent_priority_date,
                'Application Date': patent_data.application_dates,
                'Publication Date': patent_data.publication_dates,
                'Application Number': patent_data.application_number,
                'Expected Expiry Date': patent_data.expected_expiry_dates,
                'Remaining Life': patent_data.remaining_life,
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={patent}_cited_data.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name=f'{patent}_cited_data')
            workbook = writer.book
            worksheet = writer.sheets[f'{patent}_cited_data']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def download_demo_excel(req):
    wb = Workbook()
    ws = wb.active
    header_row = ["S. No.", "Publication Number", "Assignee - Standardized", "Legal Status", "Expected Expiry Dates",
                  "Remaining Life", "Cited Patents - Count", "Citing Patents - Count", "Inventors",
                  "Earliest Patent Priority Date", "Application Dates", "Publication Dates", "Application Number",
                  "CPC", "IPC", "EFAN", "Priority Country", "Assignee - Standardized"]
    ws.append(header_row)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=demo_excel_file.xlsx'
    wb.save(response)
    return response


def download_tech_demo_excel(request):
    file_path = os.path.join(settings.BASE_DIR, 'static/Ingenious e-Brain - stage demo 1.xlsm')
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(),
                                    content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(file_path)
            return response
    else:
        raise Http404("File not found")


def download_citedExl(request, project_id):
    code = Project.objects.filter(id=project_id).first().code
    top_ten_cited_patents = PatentData.objects.filter(
        prject_code=code
    ).exclude(
        citing_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]

    data = {
        'Publication Number': [patent.publication_number for patent in top_ten_cited_patents],
        'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_cited_patents],
        'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_cited_patents],
        'Legal Status': [patent.legal_status for patent in top_ten_cited_patents],
        'Inventors': [patent.inventors for patent in top_ten_cited_patents],
        'Earliest Priority Date': [patent.earliest_patent_priority_date for patent in top_ten_cited_patents],
        'Application Dates': [patent.application_dates for patent in top_ten_cited_patents],
        'Publication Dates': [patent.publication_dates for patent in top_ten_cited_patents],
        'Application Number': [patent.application_number for patent in top_ten_cited_patents],
        'Expected Expiry Date': [patent.expected_expiry_dates for patent in top_ten_cited_patents],
        'Remaining Life': [patent.remaining_life for patent in top_ten_cited_patents],
        'CPC Count': [patent.cpc for patent in top_ten_cited_patents],
        'IPC Count': [patent.ipc for patent in top_ten_cited_patents],
        'E-FAN': [patent.e_fan for patent in top_ten_cited_patents],
    }

    df = pd.DataFrame(data)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
    with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Top Ten Cited Patents')
        workbook = writer.book
        worksheet = writer.sheets['Top Ten Cited Patents']
        for i, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).apply(len).max(), len(col))
            worksheet.set_column(i, i, max_len)
    response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response


def top_ten_recent_ass_exl(request, project_id):
    code = Project.objects.filter(id=project_id).first().code
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(application_dates__year__gte=last_five_years_start, project_code=code)
        .values('assignee_standardized')
        .annotate(count=Count('assignee_standardized'))
        .order_by('-count')[:10]
    )
    ass_list = []
    for dictq in top_assignees_last_five_years:
        ass_list.append(dictq['assignee_standardized'])
    top_ten_ass = PatentData.objects.filter(assignee_standardized__in=ass_list).order_by('assignee_standardized')
    if request.GET.get('display'):
        context = {
            'top_recent_ass_view': top_ten_ass,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            'Publication Number': [patent.publication_number for patent in top_ten_ass],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_ass],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_ass],
            'Legal Status': [patent.legal_status for patent in top_ten_ass],
            'Inventors': [patent.inventors for patent in top_ten_ass],
            'Earliest Priority Date': [patent.earliest_patent_priority_date for patent in top_ten_ass],
            'Application Dates': [patent.application_dates for patent in top_ten_ass],
            'Publication Dates': [patent.publication_dates for patent in top_ten_ass],
            'Application Number': [patent.application_number for patent in top_ten_ass],
            'CPC Count': [patent.cpc for patent in top_ten_ass],
            'IPC Count': [patent.ipc for patent in top_ten_ass],
            'E-FAN': [patent.e_fan for patent in top_ten_ass],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name='top_ten_cited_patents')
            workbook = writer.book
            worksheet = writer.sheets['top_ten_cited_patents']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def top_ten_ass_exl(request, project_id):
    code = Project.objects.filter(id=project_id).first().code
    data = PatentData.objects.filter(project_code=code)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    ass_list = []
    for dictq in data:
        ass_list.append(dictq['assignee_standardized'])
    top_ten_ass = PatentData.objects.filter(project_code=code, assignee_standardized__in=ass_list).order_by(
        'assignee_standardized')
    if request.GET.get('display'):
        context = {
            'top_ten_ass_view': top_ten_ass,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            # 'Project Code': [patent.project_code for patent in top_ten_ass],
            'Publication Number': [patent.publication_number for patent in top_ten_ass],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_ass],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_ass],
            'Legal Status': [patent.legal_status for patent in top_ten_ass],
            'Inventors': [patent.inventors for patent in top_ten_ass],
            'Earliest Priority Date': [patent.earliest_patent_priority_date for patent in top_ten_ass],
            'Application Dates': [patent.application_dates for patent in top_ten_ass],
            'Publication Dates': [patent.publication_dates for patent in top_ten_ass],
            'Application Number': [patent.application_number for patent in top_ten_ass],
            'CPC Count': [patent.cpc for patent in top_ten_ass],
            'IPC Count': [patent.ipc for patent in top_ten_ass],
            'E-FAN': [patent.e_fan for patent in top_ten_ass],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=top_ten_assignee.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name='top_ten_assignee')
            # Get the xlsxwriter workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['top_ten_assignee']
            # Set the column widths
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def top_ten_cpc_exl(req, project_id):
    code = Project.object.filter(id=project_id).first().code
    patent_data_queryset = PatentData.objects.filter(project_code=code)
    cpc_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        cpc_values = patent_data.cpc.split('|') if patent_data.cpc else []
        for cpc_value in cpc_values:
            cpc_code = cpc_value.strip()
            cpc_counts_from_db[cpc_code] += 1
    cpc_counts_dict_ws = dict(cpc_counts_from_db)
    sorted_cpc_counts = dict(sorted(cpc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    cpc_counts_dict = dict(list(sorted_cpc_counts.items())[:10])
    cpc_keys_list = list(cpc_counts_dict.keys())
    top_ten_cpc = PatentData.objects.filter(Q(cpc__in=cpc_keys_list), project_code=code).order_by(
        'cpc')
    if req.GET.get('display'):
        context = {
            'top_ten_cpc': top_ten_cpc,
        }
        return render(req, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            'Publication Number': [patent.publication_number for patent in top_ten_cpc],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_cpc],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_cpc],
            'Legal Status': [patent.legal_status for patent in top_ten_cpc],
            'Inventors': [patent.inventors for patent in top_ten_cpc],
            'Earliest Priority Date': [patent.earliest_patent_priority_date for patent in top_ten_cpc],
            'Application Dates': [patent.application_dates for patent in top_ten_cpc],
            'Publication Dates': [patent.publication_dates for patent in top_ten_cpc],
            'Application Number': [patent.application_number for patent in top_ten_cpc],
            'CPC Count': [patent.cpc for patent in top_ten_cpc],
            'IPC Count': [patent.ipc for patent in top_ten_cpc],
            'E-FAN': [patent.e_fan for patent in top_ten_cpc],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=Top Ten CPC.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name='Top Ten CPC')
            # Get the xlsxwriter workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Top Ten CPC']

            # Set the column widths
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

        return response


def top_ten_ipc_exl(req, project_id):
    code = Project.objects.filter(id=project_id).first().code
    patent_data_queryset = PatentData.objects.filter(project_code=code)
    ipc_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        ipc_values = patent_data.ipc.split('|') if patent_data.cpc else []
        for ipc_value in ipc_values:
            ipc_code = ipc_value.strip()
            ipc_counts_from_db[ipc_code] += 1

    ipc_counts_dict_ws = dict(ipc_counts_from_db)
    sorted_ipc_counts = dict(sorted(ipc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    ipc_counts_dict = dict(list(sorted_ipc_counts.items())[:10])
    ipc_keys_list = list(ipc_counts_dict.keys())
    top_ten_ipc = PatentData.objects.filter(cpc__in=ipc_keys_list, project_code=code)
    if req.GET.get('display'):
        context = {
            'top_ten_ipc': top_ten_ipc,
        }
        return render(req, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            'Publication Number': [patent.publication_number for patent in top_ten_ipc],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_ipc],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=Top Ten IPC.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            # Convert the dataframe to an XlsxWriter Excel object
            df.to_excel(writer, index=False, sheet_name='Top Ten IPC')
            # Get the xlsxwriter workbook and worksheet objects
            workbook = writer.book
            worksheet = writer.sheets['Top Ten IPC']

            # Set the column widths
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def download_excel_view(req):
    status = req.GET.get('status')
    patents = PatentData.objects.filter(legal_status=status)
    data = {
        'Publication Number': list(patents.values_list('publication_number', flat=True)),
        'Assignee Standardized': list(patents.values_list('assignee_standardized', flat=True)),
        'Legal Status': list(patents.values_list('legal_status', flat=True)),
        'Expected Expiry Date': list(patents.values_list('expected_expiry_dates', flat=True)),
        'Remaining Life': list(patents.values_list('remaining_life', flat=True)),
        'Cited Patent': list(patents.values_list('cited_patents_count', flat=True)),
        'Citing Patent': list(patents.values_list('citing_patents_count', flat=True)),
        'Inventors': list(patents.values_list('inventors', flat=True)),
        'Earliest Priority Date': list(patents.values_list('earliest_patent_priority_date', flat=True)),
        'Application Date': list(patents.values_list('application_dates', flat=True)),
        'Publication Date': list(patents.values_list('publication_dates', flat=True)),
        'CPC': list(patents.values_list('cpc', flat=True)),
        'IPC': list(patents.values_list('ipc', flat=True)),
        'E_FAN': list(patents.values_list('e_fan', flat=True)),
        'Priority Country': list(patents.values_list('priority_country', flat=True)),
    }
    df = pd.DataFrame(data)
    output = BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Sheet1', index=False)
    writer._save()
    output.seek(0)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename={status}_data.xlsx'
    with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name=f'{status}_data')
        workbook = writer.book
        worksheet = writer.sheets[f'{status}_data']
        for i, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).apply(len).max(), len(col))
            worksheet.set_column(i, i, max_len)
    response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response


def fetch_data_view(request):
    status = request.GET.get('status')
    patents = PatentData.objects.filter(legal_status=status)
    data = [
        {
            'publication_number': patent.publication_number,
            'assignee_standardized': patent.assignee_standardized,
            'legal_status': patent.legal_status,
            'expected_expiry_dates': patent.expected_expiry_dates,
            'remaining_life': patent.remaining_life,
            'cited_patents_count': patent.cited_patents_count,
            'citing_patents_count': patent.citing_patents_count,
            'inventors': patent.inventors,
            'earliest_patent_priority_date': patent.earliest_patent_priority_date,
            'application_dates': patent.application_dates,
            'publication_dates': patent.publication_dates,
            'cpc': patent.cpc,
            'ipc': patent.ipc,
            'e_fan': patent.e_fan,
            'priority_country': patent.priority_country,
        }
        for patent in patents
    ]
    return JsonResponse(data, safe=False)


@request.validator
def bibliographic_charts(req, project_id):
    context = {}
    try:
        project_code_qs = Project.objects.filter(id=project_id).first()
        process_excel_data(context, req=req, project_id=project_code_qs.code)
        user_instance = CustomUser.objects.get(id=req.session.get('logged_in_user_id'))
        context['user_instance'] = user_instance
        context['project_id'] = project_id
        context['project_name'] = project_code_qs.name
        if req.method == 'POST':
            uploaded_media = req.FILES.get('patient_data')
            if uploaded_media:
                try:
                    user_id = user_instance.id
                    # celery task
                    # process_excel_data_task.delay(user_id, first_row_project_code, file_content)
                    df = pd.read_excel(uploaded_media, engine='openpyxl')
                    patent_data_rows = []
                    user_instance = CustomUser.objects.get(id=user_id)
                    if PatentData.objects.filter(project_code=project_code_qs.code):
                        PatentData.objects.filter(project_code=project_code_qs.code).delete()
                    for index, row in df.iterrows():
                        application_date_str = row['Application Dates']
                        publication_date_str = row['Publication Dates']
                        expected_expiry_str = row['Expected Expiry Dates']
                        earliest_patent_priority_str = row['Earliest Patent Priority Date']
                        application_dates = pd.NaT if pd.isna(application_date_str) else pd.to_datetime(
                            application_date_str, errors='coerce')
                        publication_dates = pd.NaT if pd.isna(publication_date_str) else pd.to_datetime(
                            publication_date_str, errors='coerce')
                        expected_expiry_dates = pd.NaT if pd.isna(expected_expiry_str) else pd.to_datetime(
                            expected_expiry_str, errors='coerce')
                        earliest_patent_priority_date = pd.NaT if pd.isna(
                            earliest_patent_priority_str) else pd.to_datetime(
                            earliest_patent_priority_str, errors='coerce')
                        remaining_life = None
                        if not math.isnan(row['Remaining Life']):
                            remaining_life = row['Remaining Life']
                        citing_patents_count = None
                        if not math.isnan(row['Citing Patents - Count']):
                            citing_patents_count = row['Citing Patents - Count']
                        cited_patents_count = None
                        if not math.isnan(row['Cited Patents - Count']):
                            cited_patents_count = row['Cited Patents - Count']
                        patent_data_dict = {
                            'user': user_instance,
                            'application_dates': handle_nat(application_dates),
                            'publication_dates': handle_nat(publication_dates),
                            'expected_expiry_dates': handle_nat(expected_expiry_dates),
                            'earliest_patent_priority_date': handle_nat(earliest_patent_priority_date),
                            'publication_number': row['Publication Number'],
                            'assignee_standardized': row['Assignee - Standardized'],
                            'legal_status': row['Legal Status'],
                            'remaining_life': remaining_life,
                            'cited_patents_count': cited_patents_count,
                            'citing_patents_count': citing_patents_count,
                            'inventors': row['Inventors'],
                            'application_number': row['Application Number'],
                            'cpc': row['CPC'],
                            'ipc': row['IPC'],
                            'e_fan': row['EFAN'],
                            'project_code': project_code_qs.code
                        }
                        patent_data_rows.append(patent_data_dict)
                    PatentData.objects.bulk_create([
                        PatentData(**data) for data in patent_data_rows
                    ])
                    process_excel_data(context, req=req, project_id=project_code_qs.code)
                except Exception as e:
                    print(f"Error processing uploaded file: {str(e)}")
                    return HttpResponseServerError("Error processing uploaded file. Please try again.")
        return render(req, 'pages/charts/bibliographic_charts.html', context)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return HttpResponseServerError("An unexpected error occurred. Please try again.")


def process_excel_data(context, req, project_id):
    """
    Process the Excel data to generate various charts.

    Args:
        df (DataFrame): The DataFrame containing bibliographic data.
        context (dict): The context dictionary to store chart data.

    """

    user_qs = get_object_or_404(CustomUser, id=req.session.get('logged_in_user_id'))
    project = get_object_or_404(Project, code=project_id)
    if not (
            UserProjectAssociation.objects.filter(user=user_qs, projects=project).exists() or
            ClientProjectAssociation.objects.filter(client=user_qs, projects=project).exists() or
            KeyAccountManagerProjectAssociation.objects.filter(key_account_manager=user_qs, projects=project).exists()
    ):
        return HttpResponse("You are not authorized to view data for this project.")
    data = PatentData.objects.filter(project_code=project_id)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(project_code=project_id, application_dates__year__gte=last_five_years_start)
        .values('assignee_standardized')
        .annotate(count=Count('assignee_standardized'))
        .order_by('-count')[:10]
    )
    context.update({
        'recent_assignees_last_five_years': top_assignees_last_five_years,
        'top_assignees': process_assignees(req=req, project_code=project_id),
        'top_assignees_dict': data,
        'top_assignees_last_five_years': process_assignees_last_five_years(request=req, project_id=project_id),
        'legal_status_counts': get_legal_status_count(req, project_id=project_id),
        'top_cited_patents': get_top_cited_count(req, project_id),
        'top_citing_patents': get_top_citing_count(req, project_id),
        'year_wise_count': get_year_with_publication(req, project_id),
        'year_wise_exp_date': get_year_with_exp_date(req, project_id),
        'process_top_cited_patent': get_top_cited_count(req, project_id),
        'get_country_code_count': get_country_code_count(req, project_id),
        'get_country_code_counts_from_db': get_country_code_counts_from_db(req, project_id),
        'get_cpc_counts_from_db': get_cpc_counts_from_db(req, project_id),
        'get_ipc_counts': get_ipc_counts(req, project_id)
    })
    # assignee_legal_status_counts = {}
    # cpc_assignee_counts = {}
    #
    # for _, row in df.iterrows():
    #     assignee = row['Assignee - Standardized']
    #     legal_status = row['Legal Status']
    #     if assignee not in assignee_legal_status_counts:
    #         assignee_legal_status_counts[assignee] = Counter()
    #     assignee_legal_status_counts[assignee][legal_status] += 1
    #
    #     cpc_values = str(row['CPC']).replace(' ', '').split('|')
    #     for cpc_value in cpc_values:
    #         cpc_code = cpc_value[:4]
    #
    #         if cpc_code not in cpc_assignee_counts:
    #             cpc_assignee_counts[cpc_code] = Counter()
    #         cpc_assignee_counts[cpc_code][assignee] += 1
    #
    # context['assignee_legal_status_counts'] = {
    #     assignee: dict(status_counts) for assignee, status_counts in
    #     assignee_legal_status_counts.items()
    # }
    # context['cpc_assignee_counts'] = {
    #     cpc_code: dict(assignee_counts) for cpc_code, assignee_counts in
    #     cpc_assignee_counts.items()
    # }


def get_country_code_count(req, project_id):
    patent_data_queryset = PatentData.objects.filter(project_code=project_id)
    assignee_country_counts_from_db = {}
    for patent_data in patent_data_queryset:
        assignee = patent_data.assignee_standardized
        publication_number = patent_data.publication_number
        country_code = publication_number[:2]
        if assignee not in assignee_country_counts_from_db:
            assignee_country_counts_from_db[assignee] = Counter()
        assignee_country_counts_from_db[assignee][country_code] += 1
    return assignee_country_counts_from_db


def get_ipc_counts(req, project_id):
    patent_data_queryset = PatentData.objects.filter(project_code=project_id)
    ipc_counts_from_db = Counter()

    for patent_data in patent_data_queryset:
        ipc_values = patent_data.ipc.split('|') if patent_data.ipc else []

        for ipc_value in ipc_values:
            if ipc_value.strip().upper() == 'NAN':
                continue

            ipc_code = ipc_value.strip()[:4]
            ipc_counts_from_db[ipc_code] += 1

    ipc_counts_dict_ws = dict(ipc_counts_from_db)
    sorted_ipc_counts = dict(sorted(ipc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    ipc_counts_dict = dict(list(sorted_ipc_counts.items())[:10])
    return ipc_counts_dict


def get_cpc_counts_from_db(req, project_id):
    patent_data_queryset = PatentData.objects.filter(project_code=project_id)
    cpc_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        cpc_values = patent_data.cpc.split('|') if patent_data.cpc else []
        for cpc_value in cpc_values:
            # Skip processing if the cpc_value is 'nan'
            if cpc_value.strip().upper() == 'NAN':
                continue
            cpc_code = cpc_value.strip()[:4]
            cpc_counts_from_db[cpc_code] += 1
    cpc_counts_dict_ws = dict(cpc_counts_from_db)
    sorted_cpc_counts = dict(sorted(cpc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    cpc_counts_dict = dict(list(sorted_cpc_counts.items())[:10])
    req.session['cpc_counts_dict'] = cpc_counts_dict
    return cpc_counts_dict


def get_country_code_counts_from_db(req, project_id):
    patent_data_queryset = PatentData.objects.filter(project_code=project_id)
    country_code_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        publication_number = patent_data.publication_number
        if publication_number is None or len(publication_number) < 2:
            continue
        country_code = publication_number[:2]
        country_code_counts_from_db[country_code] += 1
    country_code_counts_dict = dict(country_code_counts_from_db)
    return country_code_counts_dict


def get_legal_status_count(req, project_id):
    patent_data_queryset = PatentData.objects.filter(project_code=project_id)
    legal_status_counts = patent_data_queryset.values('legal_status').annotate(count=Count('legal_status'))
    legal_status_counts_dict = {item['legal_status']: item['count'] for item in legal_status_counts}
    all_legal_statuses = ['PENDING', 'EXPIRED', 'PCT', 'GRANTED']
    for legal_status in all_legal_statuses:
        legal_status_counts_dict.setdefault(legal_status, 0)
    return legal_status_counts_dict


def download_excel_file(request, project_id):
    project_code = Project.objects.filter(code=project_id).first().code
    top_ten_cited_patents = PatentData.objects.filter(project_code=project_code).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]

    if request.GET.get('display'):
        context = {
            'top_ten_cited_patents': top_ten_cited_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            'Publication Number': [patent.publication_number for patent in top_ten_cited_patents],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_cited_patents],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_cited_patents],
            'Legal Status': [patent.legal_status for patent in top_ten_cited_patents],
            'Application Dates': [patent.application_dates for patent in top_ten_cited_patents],
            'Publication Dates': [patent.publication_dates for patent in top_ten_cited_patents],
            'Application Number': [patent.application_number for patent in top_ten_cited_patents],
            'CPC Count': [patent.cpc for patent in top_ten_cited_patents],
            'IPC Count': [patent.ipc for patent in top_ten_cited_patents],
            'EFAN': [patent.e_fan for patent in top_ten_cited_patents],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Top Ten Cited Patents')
            workbook = writer.book
            worksheet = writer.sheets['Top Ten Cited Patents']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def download_citing_excel_file(request, project_id):
    project_code = Project.objects.filter(id=project_id).first().code
    top_ten_citing_patents = PatentData.objects.filter(project_code=project_code).exclude(
        cited_patents_count__isnull=True
    ).order_by('-citing_patents_count')[:10]
    if request.GET.get('display'):
        context = {
            'top_ten_citing_patents': top_ten_citing_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            'Publication Number': [patent.publication_number for patent in top_ten_citing_patents],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_citing_patents],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_citing_patents],
            'Legal Status': [patent.legal_status for patent in top_ten_citing_patents],
            'Application Dates': [patent.application_dates for patent in top_ten_citing_patents],
            'Publication Dates': [patent.publication_dates for patent in top_ten_citing_patents],
            'Expected Expiry dates': [patent.expected_expiry_dates for patent in top_ten_citing_patents],
            'Application Number': [patent.application_number for patent in top_ten_citing_patents],
            'CPC Count': [patent.cpc for patent in top_ten_citing_patents],
            'IPC Count': [patent.ipc for patent in top_ten_citing_patents],
            'EFAN': [patent.e_fan for patent in top_ten_citing_patents],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=download_citing_excel_file.xlsx'
        with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='top ten citing')
            workbook = writer.book
            worksheet = writer.sheets['top ten citing']
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).apply(len).max(), len(col))
                worksheet.set_column(i, i, max_len)
        response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


def get_year_wise_excel(req, project_id):
    project_code = Project.objects.filter(id=project_id).first().code
    year_counts = PatentData.objects.filter(project_code=project_code).annotate(
        publication_year=ExtractYear('publication_dates')
    ).values('publication_year').annotate(
        count=Count('id')
    ).order_by('-publication_year')

    data = {
        'Publication Number': [patent.publication_number for patent in year_counts],
        'Assignee Standardized': [patent.assignee_standardized for patent in year_counts],
        'Cited Patents Count': [patent.cited_patents_count for patent in year_counts],
        'Legal Status': [patent.legal_status for patent in year_counts],
        'Application Dates': [patent.application_dates for patent in year_counts],
        'Publication Dates': [patent.publication_dates for patent in year_counts],
        'Application Number': [patent.application_number for patent in year_counts],
        'CPC Count': [patent.cpc for patent in year_counts],
        'IPC Count': [patent.ipc for patent in year_counts],
        'EFAN': [patent.e_fan for patent in year_counts],
    }
    df = pd.DataFrame(data)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=year_wise_patents.xlsx'
    with pd.ExcelWriter(response, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Year Wise Patents')
        workbook = writer.book
        worksheet = writer.sheets['Year Wise Patents']
        for i, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).apply(len).max(), len(col))
            worksheet.set_column(i, i, max_len)
    response['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response


def get_top_citing_count(req, project_id):
    citing_patents_dict = {}
    top_ten_citing_patents = PatentData.objects.filter(
        project_code=project_id
    ).exclude(
        citing_patents_count__isnull=True
    ).order_by('-citing_patents_count')[:10]

    for patent_data in top_ten_citing_patents:
        if patent_data.citing_patents_count is None:
            continue

        citing_patents_dict[patent_data.publication_number] = {
            "count": patent_data.citing_patents_count,
            "assignee": patent_data.assignee_standardized
        }
    return citing_patents_dict


def get_top_cited_count(req, project_id):
    cited_patents_dict = {}
    top_ten_cited_patents = PatentData.objects.filter(
        project_code=project_id
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]

    for patent_data in top_ten_cited_patents:
        if patent_data.cited_patents_count is None:
            continue
        cited_patents_dict[patent_data.publication_number] = {
            "count": patent_data.cited_patents_count,
            "assignee": patent_data.assignee_standardized
        }
    return cited_patents_dict


def get_year_with_publication(req, project_id):
    year_counts = PatentData.objects.filter(project_code=project_id).annotate(
        publication_year=ExtractYear('publication_dates')
    ).values('publication_year').annotate(
        count=Count('id')
    ).order_by('-publication_year')
    year_wise_count = {item['publication_year']: item['count'] for item in year_counts}
    return dict(year_wise_count)


def get_year_with_exp_date(req, project_id):
    year_counts = PatentData.objects.filter(
        Q(expected_expiry_dates__isnull=False) | Q(expected_expiry_dates__isnull=True),
        project_code=project_id
    ).annotate(
        expected_expiry_date=ExtractYear('expected_expiry_dates')
    ).values('expected_expiry_date').annotate(count=Count('id'))

    year_wise_exp_date = defaultdict(int)
    for item in year_counts:
        if item['expected_expiry_date'] is None:
            continue
        year_wise_exp_date[item['expected_expiry_date']] += item['count']
    return dict(year_wise_exp_date)


def process_assignees(req, project_code):
    data = PatentData.objects.filter(project_code=project_code).exclude(
        assignee_standardized__isnull=True)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    result = [{'Assignee - Standardized': item['assignee_standardized'], 'count': item['count']} for item in data]
    return result


def process_assignees_last_five_years(request, project_id):
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(project_code=project_id, application_dates__year__gte=last_five_years_start)
        .exclude(application_dates__isnull=True)  # Exclude entries with null application_dates
        .values('assignee_standardized')
        .annotate(count=Count('assignee_standardized'))
        .order_by('-count')[:10]
    )

    top_assignees_last_five_years_list = list(top_assignees_last_five_years)
    return top_assignees_last_five_years_list


def process_legal_status(df):
    """
    process_legal_status
    """
    legal_status_counts = df['Legal Status'].value_counts()
    pending_count = legal_status_counts.get('PENDING', 0)
    expired_count = legal_status_counts.get('EXPIRED', 0)
    pct_count = legal_status_counts.get('PCT', 0)
    granted_count = legal_status_counts.get('GRANTED', 0)
    return {
        'PENDING': pending_count,
        'EXPIRED': expired_count,
        'PCT': pct_count,
        'GRANTED': granted_count
    }


def process_top_cited_patent(df):
    """
    process_top_cited_patent
    """
    cited_patents_counts = df.groupby('Publication Number')['Cited Patents - Count'].sum()
    top_cited_patents = cited_patents_counts.sort_values(ascending=False).head(10).reset_index()
    return top_cited_patents.set_index('Publication Number')['Cited Patents - Count'].to_dict()


@request.validator
def logout(req):
    """
    Delete all sessions when user is logged out.
    """
    sessions = Session.objects.all()
    for session in sessions:
        session.delete()
        return redirect('login')


@request.validator
def user_profile(req):
    """
    User Profile
    """
    user_id = req.session.get('logged_in_user_id')
    user_qs = CustomUser.objects.get(id=user_id)
    if user_qs.roles == 'client':
        client_project_associations = ClientProjectAssociation.objects.filter(client_id=user_qs.id)
        total_projects = client_project_associations.values_list('projects', flat=True)
        completed_projects = Project.objects.filter(id__in=total_projects, status='Completed')
        in_progress_projects = Project.objects.filter(id__in=total_projects, status='In Progress')

        completed = CustomUser.objects.filter(
            client_project_associations__projects__in=completed_projects)

        in_progress = CustomUser.objects.filter(
            client_project_associations__projects__in=in_progress_projects)

    if user_qs.roles == 'project_manager':
        manager_project_associations = UserProjectAssociation.objects.filter(user_id=user_qs.id)
        total_projects = manager_project_associations.values_list('projects', flat=True)
        completed_projects = Project.objects.filter(id__in=total_projects, status='Completed')
        in_progress_projects = Project.objects.filter(id__in=total_projects, status='In Progress')
        completed = CustomUser.objects.filter(
            client_project_associations__projects__in=completed_projects)

        in_progress = CustomUser.objects.filter(
            client_project_associations__projects__in=in_progress_projects)

    if user_qs.roles == 'key_account_holder':
        kam_project_associations = KeyAccountManagerProjectAssociation.objects.filter(key_account_manager_id=user_qs.id)
        total_projects = kam_project_associations.values_list('projects', flat=True)
        completed_projects = Project.objects.filter(id__in=total_projects, status='Completed')
        in_progress_projects = Project.objects.filter(id__in=total_projects, status='In Progress')
        completed = CustomUser.objects.filter(
            client_project_associations__projects__in=completed_projects)

        in_progress = CustomUser.objects.filter(
            client_project_associations__projects__in=in_progress_projects)

    context = {
        'iebs_user': user_qs,
        'total_projects': total_projects,
        'completed': completed,
        'in_prog': in_progress,
    }
    return render(req, 'pages/onboard/profile.html', context)


@request.validator
def admin_profile(req):
    """
    User Profile
    """
    user_qs = User.objects.filter(is_superuser=True).first()
    total_projects = Project.objects.all()
    completed = Project.objects.filter(status='Completed')
    in_progress = Project.objects.filter(status='In Progress')
    context = {
        'iebs_user': user_qs,
        'total_projects': total_projects,
        'completed': completed,
        'in_prog': in_progress,
    }
    return render(req, 'pages/onboard/profile.html', context)


@request.validator
def project_client_association(req):
    """
    User Profile
    """
    project_association = {}
    user_id = req.session.get('logged_in_user_id')
    user_qs = CustomUser.objects.get(id=user_id)

    if user_qs.roles != 'Client':
        clients = CustomUser.objects.filter(roles=CustomUser.CLIENT, is_superuser=False)

        # Fetch project association based on user's role
        if user_qs.roles == 'project_manager':
            try:
                project_association = UserProjectAssociation.objects.get(user=user_id)
            except UserProjectAssociation.DoesNotExist:
                # Handle case where project manager is not associated with any project
                project_association = None

        elif user_qs.roles == 'key_account_holder':
            try:
                project_association = KeyAccountManagerProjectAssociation.objects.get(user=user_id)
            except KeyAccountManagerProjectAssociation.DoesNotExist:
                # Handle case where key account manager is not associated with any project
                project_association = None

        # Check if project_association is not None before accessing its attributes
        if project_association:
            associated_projects = project_association.projects.all()
            associated_project_ids = [project.id for project in associated_projects]

            if req.method == 'POST':
                client_username = req.POST.get('client')
                project_ids = req.POST.getlist('projects')
                client = get_object_or_404(CustomUser, username=client_username, roles=CustomUser.CLIENT)
                projects = [get_object_or_404(Project, id=int(project_id)) for project_id in project_ids[0].split(',')]
                client_project_association = ClientProjectAssociation.objects.create(client=client,
                                                                                     allocated_by=user_qs)
                client_project_association.projects.set(projects)

            return render(req, 'pages/projects/project_client_association.html',
                          {'clients': clients, 'associated_projects': associated_projects,
                           'associated_project_ids': associated_project_ids})

        else:
            # Handle case where user is not associated with any project
            return render(req, 'pages/projects/project_client_association.html',
                          {'clients': clients, 'message': 'You are not associated with any projects.'})


@request.validator
def get_associated_projects(req):
    """


    """
    selected_client = req.GET.get('client')
    associated_projects = ClientProjectAssociation.objects.filter(client__username=selected_client).values_list(
        'projects', flat=True)
    associated_project_ids = [project for project in associated_projects]
    return JsonResponse({'associated_projects': associated_project_ids})

@csrf_exempt
def doc_upload(request, project_id):
    """


    """
    uploaded_by = request.session.get('logged_in_user_id')
    project_name = Project.objects.filter(id=project_id).first().name
    user_role = CustomUser.objects.filter(id=uploaded_by).first().roles
    uploaded_files = ProjectReports.objects.filter(project_id=project_id)
    if request.method == 'POST':
        if request.FILES.get('proposal_report'):
            proposal_file = request.FILES['proposal_report']
            ProjectReports.objects.create(
                file=proposal_file,
                file_name=proposal_file.name,
                file_type='Proposal',
                uploaded_by_id=uploaded_by,
                project_id=project_id
            )

        if request.FILES.get('interim_report'):
            interim_file = request.FILES['interim_report']
            ProjectReports.objects.create(
                file=interim_file,
                file_name=interim_file.name,
                file_type='Interim Report',
                uploaded_by_id=uploaded_by,
                project_id=project_id
            )

        if request.FILES.get('final_report'):
            final_file = request.FILES['final_report']
            ProjectReports.objects.create(
                file=final_file,
                file_name=final_file.name,
                file_type='Final Report',
                uploaded_by_id=uploaded_by,
                project_id=project_id
            )
        return redirect('doc_upload', project_id=project_id)
    return render(request, 'pages/projects/upload_documents.html',
                  {"project_name": project_name, "uploaded_files": uploaded_files, "user_role": user_role})


def download_file(request, project_id):
    """


    """
    uploaded_file = get_object_or_404(ProjectReports, id=project_id)
    response = HttpResponse(uploaded_file.file, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{uploaded_file.file_name}"'
    return response


# ======================NEW ADMIN PANNEL==========
@csrf_exempt
def add_project(request):
    if request.method == 'POST':
        project_name = request.POST.get('projectName')
        projectDescription = request.POST.get('projectDescription')
        projectCode = request.POST.get('projectCode')
        projectScope = request.POST.get('projectScope')
        projectStatus = request.POST.get('projectStatus')
        project = Project.objects.create(
            name=project_name,
            code=projectCode,
            scope=projectScope,
            description=projectDescription,
            status=projectStatus,

        )
        return redirect('admin_project_listing')
    return render(request, 'pages/superadmin/add_project.html')


@request.validator
def user_listing(request):
    user_obj = CustomUser.objects.all()
    return render(request, 'pages/superadmin/user_listing.html', {"user_obj": user_obj})


@request.validator
def association_listing(request, project_id):
    project_obj = Project.objects.filter(id=project_id).first()
    associations = ClientProjectAssociation.objects.filter(projects=project_obj).select_related('client')

    associated_managers = UserProjectAssociation.objects.filter(projects=project_obj).select_related('user')

    associated_kam = KeyAccountManagerProjectAssociation.objects.filter(projects=project_obj).select_related(
        'key_account_manager')
    clients = [association.client for association in associations]
    managers = [association.user for association in associated_managers]
    kam = [association.key_account_manager for association in associated_kam]
    return render(request, 'pages/superadmin/association_listing.html',
                  {"clients": clients, "managers": managers, "kams": kam, "project_obj": project_obj})


@request.validator
def add_user(request):
    if request.method == 'POST':
        username = request.POST.get('userName')
        password = request.POST.get('userPassword')
        email = request.POST.get('userEmail')
        role = request.POST.get('userRoles')
        business_unit = request.POST.get('businessUnit')
        try:
            user = CustomUser.objects.create_user(username=username, email=email, password=password)
            user.roles = role
            user.business_unit = business_unit
            user.save()
            return JsonResponse({'status': 'success', 'message': 'User created successfully'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return render(request, 'pages/superadmin/create_user.html')


@request.validator
def edit_user(request, user_id):
    user_obj = CustomUser.objects.filter(id=user_id).first()
    if request.method == 'POST':
        username = request.POST.get('userName')
        useremail = request.POST.get('userEmail')
        password = request.POST.get('userPassword')
        roles = request.POST.get('userRoles')
        BU = request.POST.get('businessUnit')
        user_obj.username = username
        user_obj.email = useremail
        user_obj.roles = roles
        user_obj.business_unit = BU
        if password:
            user_obj.set_password(password)
        user_obj.updated_date = timezone.now()
        user_obj.save()
        return render(request, 'pages/superadmin/edit_user.html', {'user_obj': user_obj})
    return render(request, 'pages/superadmin/edit_user.html', {'user_obj': user_obj})


@csrf_exempt
def user_project_association(request):
    """


    """
    manager_obj = CustomUser.objects.filter(roles__in=['project_manager', 'PROJECT_MANAGER'])
    client_obj = CustomUser.objects.filter(roles__in=['client', 'CLIENT'])
    kam_obj = CustomUser.objects.filter(roles__in=['KEY_ACCOUNT_HOLDER', 'key_account_holder'])
    project_obj = Project.objects.all()
    return render(request, 'pages/superadmin/user_project_association.html',
                  {'manager_obj': manager_obj, 'client_obj': client_obj, 'kam_obj': kam_obj,
                   'project_obj': project_obj})


@csrf_exempt
def admin_project_listing(request):
    project_obj = Project.objects.all().order_by('-id')
    return render(request, 'pages/superadmin/admin_project_listing.html', {"project_obj": project_obj})


@csrf_exempt
def get_associated_users(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    # Get associated clients
    associated_clients = ClientProjectAssociation.objects.filter(projects=project).values_list('client_id', flat=True)
    # Get associated managers
    associated_managers = UserProjectAssociation.objects.filter(projects=project).values_list('user_id', flat=True)
    associated_kam = KeyAccountManagerProjectAssociation.objects.filter(projects=project).values_list(
        'key_account_manager_id', flat=True)
    return JsonResponse({
        'associated_clients': list(associated_clients),
        'associated_kam': list(associated_kam),
        'associated_managers': list(associated_managers)
    })


@csrf_exempt
def associate_users_with_project(request):
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        try:
            project = Project.objects.get(pk=project_id)
        except Project.DoesNotExist:
            return JsonResponse({'error': 'Project does not exist'}, status=404)
        selected_clients = request.POST.getlist('client_ids[]')
        selected_kam = request.POST.getlist('kam_ids[]')
        selected_managers = request.POST.getlist('manager_ids[]')
        # project.clientprojectassociation_set.clear()  # Remove existing associations
        for client_id in selected_clients:
            client = CustomUser.objects.get(pk=client_id)
            association, created = ClientProjectAssociation.objects.get_or_create(client=client)
            association.projects.add(project)
        # project.keyaccountmanagerprojectassociation_set.clear()  # Remove existing associations
        for kam_id in selected_kam:
            kam = CustomUser.objects.get(pk=kam_id)
            association, created = KeyAccountManagerProjectAssociation.objects.get_or_create(key_account_manager=kam)
            association.projects.add(project)
        # project.userprojectassociation_set.clear()  # Remove existing associations
        for manager_id in selected_managers:
            manager = CustomUser.objects.get(pk=manager_id)
            association, created = UserProjectAssociation.objects.get_or_create(user=manager)
            association.projects.add(project)
        return JsonResponse({'message': 'Users associated successfully'}, status=200)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def delete_user(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        try:
            get_object_or_404(CustomUser, id=user_id).delete()
            return JsonResponse({'status': 'success'})
        except UserProjectAssociation.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User association not found'})
        except Project.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


@csrf_exempt
def deallocate_users_ajax(request):
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        manager_id = request.POST.get('manager_id')
        project = get_object_or_404(Project, id=project_id)
        user = get_object_or_404(CustomUser, id=manager_id)
        if user.client_project_associations.filter(projects=project).exists():
            association = get_object_or_404(ClientProjectAssociation, client=user, projects=project)
        elif user.key_account_manager_project_associations.filter(projects=project).exists():
            association = get_object_or_404(KeyAccountManagerProjectAssociation, key_account_manager=user,
                                            projects=project)
        elif user.project_associations.filter(projects=project).exists():
            association = get_object_or_404(UserProjectAssociation, user=user, projects=project)
        else:
            return JsonResponse({'status': 'error', 'message': 'User not associated with the project.'}, status=400)
        association.delete()
        return JsonResponse({'status': 'success', 'message': 'Association removed successfully.'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)


@request.validator
def reports_listing(request, project_id):
    """


    """
    # uploaded_by = User.objects.filter(is_superuser=True).first().id
    project_name = Project.objects.filter(id=project_id).first().name
    user_role = 'superadmin'
    uploaded_files = ProjectReports.objects.filter(project_id=project_id)
    if request.method == 'POST':
        if request.FILES.get('proposal_report'):
            proposal_file = request.FILES['proposal_report']
            ProjectReports.objects.create(
                file=proposal_file,
                file_name=proposal_file.name,
                file_type='Proposal',
                project_id=project_id
            )

        if request.FILES.get('interim_report'):
            interim_file = request.FILES['interim_report']
            ProjectReports.objects.create(
                file=interim_file,
                file_name=interim_file.name,
                file_type='Interim Report',
                project_id=project_id
            )

        if request.FILES.get('final_report'):
            final_file = request.FILES['final_report']
            ProjectReports.objects.create(
                file=final_file,
                file_name=final_file.name,
                file_type='Final Report',
                project_id=project_id
            )
        return redirect('reports_listing', project_id=project_id)
    return render(request, 'pages/superadmin/reports_listing.html',
                  {"project_name": project_name, "uploaded_files": uploaded_files, "user_role": user_role})


def delete_report(request, file_id):
    if request.method == 'POST':
        ProjectReports.objects.get(id=file_id).delete()
        return JsonResponse({'message': 'File deleted successfully'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
