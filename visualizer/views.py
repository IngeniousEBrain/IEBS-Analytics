"""
Views for the 'visualizer' app.
"""
import json
# Third-party imports
from datetime import datetime
import collections
from collections import Counter
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from io import BytesIO
from urllib.parse import unquote
from django.core.serializers import serialize
from django.urls import reverse

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.http import HttpResponse
from django.http import HttpResponseServerError
from django.db.models import Q
from django.db.models.functions import ExtractYear
# Local imports
from .models import CustomUser, Project, PatentData, UserProjectAssociation
from .packages import request
from django.db.models import Count
from .tasks import process_excel_data_task
from django.views.decorators.csrf import csrf_exempt
import math
from openpyxl import Workbook


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


def get_user_project_data(user_id):
    """
    Fetches user-related project data.

    Args:
        user_id (int): The ID of the logged-in user.

    Returns:
        dict: Dictionary containing user-related project information.
    """
    user_qs = CustomUser.objects.filter(id=user_id).first()
    total = Project.objects.filter(userprojectassociation__user_id=user_id)
    completed_projects = Project.objects.filter(
        userprojectassociation__user_id=user_id, status__exact='Completed'
    )
    in_progress_projects = Project.objects.filter(
        userprojectassociation__user_id=user_id, status__exact='In Progress'
    )

    return {
        'user': user_qs,
        'total': total,
        'completed_projects': completed_projects,
        'in_progress_projects': in_progress_projects,
    }


@request.validator
def project_list(req):
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
    projects = Project.objects.filter(userprojectassociation__user_id=user_id)
    context = {'projects_data': projects, 'user_qs': user_qs}
    return render(req, 'pages/projects/project_listing.html', context)


def delete_project(request):
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        user_id = request.session.get('logged_in_user_id')
        try:
            user_associations = UserProjectAssociation.objects.filter(user_id=user_id)
            project_to_deallocate = Project.objects.get(id=project_id)
            for user_association in user_associations:
                user_association.projects.remove(project_to_deallocate)
            return JsonResponse({'status': 'success'})
        except UserProjectAssociation.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User association not found'})
        except Project.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Project not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@request.validator
def edit_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    context = {'project': project}
    if request.method == 'POST':
        pass
    return render(request, 'pages/projects/project_edit.html', context)


@request.validator
def completed_project_list(req):
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
    projects = Project.objects.filter(userprojectassociation__user_id=user_id, status='Completed')
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
    projects = Project.objects.filter(userprojectassociation__user_id=user_id, status='In Progress')
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


def extract_assignee_partners(req):
    assignee_partner_dict = {}
    user = req.session.get('logged_in_user_id')
    for patent_data in PatentData.objects.filter(user_id=user):
        assignee_partners_str = patent_data.assignee_standardized
        assignee, *partners = map(lambda x: x.strip().title(), assignee_partners_str.split('|'))
        if assignee in assignee_partner_dict:
            assignee_partner_dict[assignee].extend(p for p in partners if p)
        else:
            assignee_partner_dict[assignee] = [p for p in partners if p]
    return assignee_partner_dict


def get_top_assignees_by_year(req):
    top_assignees = PatentData.objects.values('assignee_standardized').annotate(
        count=Count('assignee_standardized')).order_by('-count')[:10]
    result = collections.defaultdict(dict)
    for assignee in top_assignees:
        name = assignee['assignee_standardized']
        year_wise_count = PatentData.objects.filter(assignee_standardized=name).values(
            'application_dates__year').annotate(count=Count('id'))
        for data in year_wise_count:
            year = data['application_dates__year']
            count = data['count']
            result[name][year] = count
    return result


@request.validator
def tech_charts(req):
    """
    logic for tech charts
    """
    data_pie = [1, 8, 1, 1, 7]
    labels_pie = ['TISSUE ANALYSIS', 'Herbiside LOCALIZATION', 'BIOMAKER ANALYSIS', 'CELL CLASSIFICATION',
                  'SPECIAL NONTAG']
    colors_pie = ['#084594', '#2171b5', '#4292c6', '#6baed6', '#9ecae1']
    data_donut = [5, 4, 3, 2, 1]
    labels_donut = ['Category A', 'Category B', 'Category C', 'Category D', 'Category E']
    colors_donut = ['#084594', '#2171b5', '#4292c6', '#6baed6', '#9ecae1']
    pie_trace = go.Pie(labels=labels_pie, values=data_pie, marker=dict(colors=colors_pie))
    donut_trace = go.Pie(labels=labels_donut, values=data_donut, hole=0.4, marker=dict(colors=colors_donut))

    fig_combined = make_subplots(
        rows=1, cols=2, subplot_titles=['Pie Chart', 'Donut Chart'],
        specs=[[{'type': 'domain'}, {'type': 'domain'}]]
    )
    fig_combined.add_trace(pie_trace, row=1, col=1)
    fig_combined.add_trace(donut_trace, row=1, col=2)
    fig_combined.update_layout(
        title='Pie and Donut Charts Side by Side',
        height=500,
        width=950
    )
    div_combined = fig_combined.to_html()
    # =================================
    pie_data = [5, 4, 3, 2, 1, 5, 4, 9]
    pie_labels = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
    # Extended color list
    pie_colors = ['#3498db', '#E4EBF7', '#2ecc71', '#E4EBF7', '#e74c3c', '#95a5a6', '#f1c40f', '#bdc3c7']
    # Bar chart data
    bar_data = [10, 8, 6, 4, 2]
    bar_labels = ['Category 1', 'Category 2', 'Category 3', 'Category 4', 'Category 5']
    bar_colors = ['#084594', '#2171b5', '#4292c6', '#6baed6', '#9ecae1']
    pie = go.Pie(
        labels=pie_labels,
        values=pie_data,
        marker_colors=pie_colors
    )
    # Create horizontal bar chart
    bar = go.Bar(
        y=bar_labels,
        x=bar_data,
        orientation='h',
        marker_color=bar_colors
    )

    # Create subplots
    fig = make_subplots(
        rows=1, cols=2,
        specs=[[{'type': 'domain'}, {'type': 'xy'}]])

    # Add traces
    fig.add_trace(pie, row=1, col=1)
    fig.add_trace(bar, row=1, col=2)

    # Update layout
    fig.update_layout(
        title="Combined Chart",
        width=950,
        height=600
    )

    div2 = fig.to_html()
    # =================================
    data = np.random.rand(13, 13)

    # Define the color scale (blue and white shades)
    colorscale = [[0, 'white'], [1, 'skyblue']]

    # Create the heatmap
    heatmap = go.Figure(data=go.Heatmap(
        z=data,
        colorscale=colorscale,
    ))

    # Set the layout parameters
    heatmap.update_layout(
        width=950,
        height=400,
        margin=dict(l=0, r=0, b=0, t=0),
    )

    # Show the plot
    div3 = heatmap.to_html()
    # ================================
    context = {'plot_div1': div_combined, 'div2': div2, 'div3': div3}
    return render(req, 'pages/charts/technical_chart.html', context)


# ===========================data view and download==============
@csrf_exempt
def get_q_object(assignee, partner):
    return Q(assignee_standardized__icontains=assignee) & Q(assignee_standardized__icontains=partner)


@csrf_exempt
def competitor_colab_view(request):
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
            # if 'partner_ass_date_qs' in request.session:
            #     del request.session['partner_ass_date_qs']
            data = json.loads(request.body)
            if data.get('assignee_standardized') and data.get('legal_status'):
                assignee_list = [data.get('assignee_standardized')]
                lega_status = PatentData.objects.filter(assignee_standardized__in=assignee_list,
                                                        legal_status=data.get('legal_status'))
                if data.get('type') == 'display':
                    ass_legal_status_qs = serialize('json', lega_status)
                    context = {'ass_legal_status_qs': json.loads(ass_legal_status_qs)}
                    request.session['ass_legal_status_qs'] = json.loads(ass_legal_status_qs)
                    return JsonResponse(
                        {'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
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
                                                            publication_number=data.get('publication'))
                if data.get('type') == 'display':
                    ass_pub_date_qs = serialize('json', year_wise_count)
                    context = {'ass_pub_date_qs': json.loads(ass_pub_date_qs)}
                    request.session['ass_pub_date_qs'] = json.loads(ass_pub_date_qs)
                    return JsonResponse(
                        {'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
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
                                                            application_dates__year=data.get('year'))
                if data.get('type') == 'display':
                    partner_app_date_qs = serialize('json', year_wise_count)
                    context = {'partner_app_date_qs': json.loads(partner_app_date_qs)}
                    request.session['partner_app_date_qs'] = json.loads(partner_app_date_qs)
                    return JsonResponse(
                        {'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
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
                user_id = request.session.get('logged_in_user_id')
                filtered_data = PatentData.objects.filter(user_id=user_id, citing_patents_count__isnull=False)
                top_ten_highest_citing = filtered_data.order_by('-citing_patents_count')[:10]
                top_ten_highest_citing_qs = serialize('json', top_ten_highest_citing)
                context = {'top_ten_highest_citing_qs': json.loads(top_ten_highest_citing_qs)}
                request.session['top_ten_highest_citing_qs'] = json.loads(top_ten_highest_citing_qs)
                return JsonResponse({'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
                                     'type': 'display'})
            elif data.get('type') == 'allCitedFile':
                user_id = request.session.get('logged_in_user_id')
                filtered_data = PatentData.objects.filter(user_id=user_id, citing_patents_count__isnull=False)
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

            # elif data.get('type') == 'allDisplay':
            #         print("allDisplay")
            #         data = PatentData.objects.filter(user_id=request.session.get('logged_in_user_id'))
            #         data1 = data.values('assignee_standardized').annotate(
            #             count=Count('assignee_standardized')).order_by(
            #             '-count')[:10]
            #         for item in data1:
            #             assignee_name = item['assignee_standardized']
            #             partners_list = extract_assignee_partners(request).get(assignee_name.title(), [])
            #             patents = PatentData.objects.filter(Q(assignee_standardized__in=assignee_name))
            #
            #             acontext = {'partner_ass_date_qs': list(patents)}
            #             print(acontext)
            #         patent_data = {}
            #
            #         # if data.get('type') == 'display':
            #         #     for partner in partners_list:
            #         #         q_obj = get_q_object(assignee, partner)
            #         #         patents = PatentData.objects.filter(q_obj)
            #         #         # Convert QuerySet to a list of dictionaries
            #         #         patents_data = serialize('json', patents)
            #         #         patents_list = json.loads(patents_data)
            #         #         patent_data[f"{assignee}_{partner}"] = patents_list
            #         #     context = {'patent_data': patent_data}
            #         #     request.session['patent_data'] = patent_data
            #         #     return JsonResponse(
            #         #         {'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
            #         #          'type': 'display'})

            # elif data.get('type') == 'allFile':
            #     pass
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
                        patents = PatentData.objects.filter(q_obj)
                        # Convert QuerySet to a list of dictionaries
                        patents_data = serialize('json', patents)
                        patents_list = json.loads(patents_data)
                        patent_data[f"{assignee}_{partner}"] = patents_list
                    context = {'patent_data': patent_data}
                    request.session['patent_data'] = patent_data
                    return JsonResponse(
                        {'success': True, 'data': context, 'redirect_url': reverse('competitor_colab_view'),
                         'type': 'display'})
                data_list = []
                if data.get('type') == 'file':
                    for partner in partners_list:
                        q_obj = get_q_object(assignee, partner)
                        patents = PatentData.objects.filter(q_obj)
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
def competitor_charts(req):
    data = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    data1 = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    result = []
    for item in data1:
        assignee_name = item['assignee_standardized']
        partners_list = extract_assignee_partners(req).get(assignee_name.title(), [])
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
    fig1 = go.Figure(data=go.Heatmap(
        z=partner_count_matrix,
        x=partners,
        y=assignees,
        hoverinfo='none',
        colorscale='PuBuGn',
        colorbar=dict(title='Partner Count'),
        text=[[f'<span style="color:{text_colors[i][j]}">{count}</span>' if count is not None else '' for j, count in
               enumerate(row)] for i, row in enumerate(partner_count_matrix)],
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
    result_b = get_top_assignees_by_year(req)
    data = []
    for assignee, yeardict in result_b.items():
        for year, count in yeardict.items():
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
    user_id = req.session.get('logged_in_user_id')
    filtered_data = PatentData.objects.filter(user_id=user_id, citing_patents_count__isnull=False)
    top_ten_highest_citing = filtered_data.order_by('-citing_patents_count')[:10]
    top_ten_values = [val.citing_patents_count for val in top_ten_highest_citing]
    assignee_names = [val.assignee_standardized.split('|')[0] for val in top_ten_highest_citing]
    publication_numbers = [val.publication_number for val in top_ten_highest_citing]
    cited_values = [val.cited_patents_count if val.cited_patents_count is not None else 1 for val in
                    top_ten_highest_citing]
    citation_index_values = [round(citing / cited, 2) for citing, cited in zip(top_ten_values, cited_values)]
    y_labels = [f"{assignee} | {publication}" for assignee, publication in zip(assignee_names, publication_numbers)]
    table_data = []

    for val in top_ten_highest_citing:
        assignee_name = val.assignee_standardized.split('|')[0]
        publication_number = val.publication_number
        citing_count = val.citing_patents_count
        cited_count = val.cited_patents_count if val.cited_patents_count is not None else 1
        citation_index = round(citing_count / cited_count, 2)
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
    top_assignees = PatentData.objects.values('assignee_standardized').annotate(
        count=Count('assignee_standardized')).order_by('-count')[:10]
    top_assignee_ids = [a['assignee_standardized'] for a in top_assignees]
    legal_status_counts = PatentData.objects.filter(assignee_standardized__in=top_assignee_ids).values(
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

    df = px.data.gapminder().query("year==2007")
    fig6 = px.choropleth(df, locations="iso_alpha",
                         color="lifeExp",
                         hover_name="country",
                         color_continuous_scale=px.colors.sequential.Plasma)

    # Set the height and width of the choropleth map
    fig6.update_layout(
        height=600,
        width=995
    )

    div6 = fig6.to_html(full_html=False)
    context = {'plot_div1': div1, 'plot_div2': div2, 'plot_div3': div3, 'plot_div4': div4,
               'plot_div6': div6, 'data1': data1, 'result': res, 'data': data,
               'table_data': table_data, 'legal_status_counts': legal_status_counts}
    return render(req, 'pages/charts/competitor_charts.html', context)


def handle_nat(dt):
    if pd.isna(dt):
        return None
    else:
        return dt


def download_publication_exl(request, year):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    innovators = PatentData.objects.filter(publication_dates__year=year, user_id=user_id_to_filter)
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=legal_status_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_exp_exl(request, year):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    exp_qs = PatentData.objects.filter(expected_expiry_dates__year=year, user_id=user_id_to_filter)
    for patent_data in exp_qs:
        if request.GET.get('display'):
            context = {
                'exp_qs': exp_qs,
            }
            return render(request, 'pages/charts/top_ten_ipc.html', context)
        else:
            data = {
                'Expected Expiry Date': patent_data.expected_expiry_dates,
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
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=expected_expiry_date.xlsx'
        df.to_excel(response, index=False)
        return response


def download_legal_status_exl(request, status):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    innovators = PatentData.objects.filter(legal_status=status, user_id=user_id_to_filter)
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
        df.to_excel(response, index=False)
        return response


def individual_cpc_exl(request, cpc):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    cpc_qs = PatentData.objects.filter(cpc__startswith=cpc, user_id=user_id_to_filter)
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=legal_status_data.xlsx'
        df.to_excel(response, index=False)
        return response


def individual_ipc_exl(request, ipc):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    ipc_qs = PatentData.objects.filter(ipc__startswith=ipc, user_id=user_id_to_filter)
    if request.GET.get('display'):
        context = {
            'ipc_qs': ipc_qs,
            # Add more context variables if needed
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=legal_status_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_innovative_exl(request, country):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    innovators = PatentData.objects.filter(publication_number__startswith=country, user_id=user_id_to_filter)
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename=legal_status_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_ind_citing_excel(request, patent):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_citing_patents = PatentData.objects.filter(
        publication_number=patent, user_id=user_id_to_filter
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={patent}_citing_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_top_assignee_exl(request, assignee):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_assignees = PatentData.objects.filter(
        assignee_standardized=assignee, user_id=user_id_to_filter
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={assignee}_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_recent_assignee_exl(request, assignee):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_assignees = PatentData.objects.filter(
        assignee_standardized=assignee, user_id=user_id_to_filter
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={assignee}_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_ind_cited_excel(request, patent):
    data_list = []
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_citing_patents = PatentData.objects.filter(
        publication_number=patent, user_id=user_id_to_filter
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
                'CPC': patent_data.cpc,
                'IPC': patent_data.ipc,
                'E-Fan': patent_data.e_fan,
            }
            data_list.append(data)
        df = pd.DataFrame(data_list)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = f'attachment; filename={patent}_cited_data.xlsx'
        df.to_excel(response, index=False)
        return response


def download_demo_excel(req):
    wb = Workbook()
    ws = wb.active
    header_row = ["S. No.", "Publication Number", "Assignee - Standardized", "Legal Status", "Expected Expiry Dates",
                  "Remaining Life", "Cited Patents - Count", "Citing Patents - Count", "Inventors",
                  "Earliest Patent Priority Date", "Application Dates", "Publication Dates", "Application Number",
                  "CPC", "IPC", "EFAN", "Priority Country", "Assignee - Standardized", "Project–Code"]
    ws.append(header_row)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=demo_excel_file.xlsx'
    wb.save(response)
    return response


def download_citedExl(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_cited_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        citing_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]
    data = {
        # 'Project Code': [patent.project_code for patent in top_ten_cited_patents],
        'Publication Number': [patent.publication_number for patent in top_ten_cited_patents],
        'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_cited_patents],
        'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_cited_patents],
        'Legal Status': [patent.legal_status for patent in top_ten_cited_patents],
        'Inventors': [patent.inventors for patent in top_ten_cited_patents],
        'Earliest Priority Date': [patent.earliest_patent_priority_date for patent in top_ten_cited_patents],
        'Application Dates': [patent.application_dates for patent in top_ten_cited_patents],
        'Publication Dates': [patent.publication_dates for patent in top_ten_cited_patents],
        'Application Number': [patent.application_number for patent in top_ten_cited_patents],
        'CPC Count': [patent.cpc for patent in top_ten_cited_patents],
        'IPC Count': [patent.ipc for patent in top_ten_cited_patents],
        'E-FAN': [patent.e_fan for patent in top_ten_cited_patents],
    }
    df = pd.DataFrame(data)
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
    df.to_excel(response, index=False, sheet_name='Top Ten Cited Patents')
    return response


def top_ten_recent_ass_exl(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(user_id=user_id_to_filter, application_dates__year__gte=last_five_years_start)
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
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        df.to_excel(response, index=False, sheet_name='Top Ten Cited Patents')
        return response


def top_ten_ass_exl(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    data = PatentData.objects.filter(user_id=user_id_to_filter)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    ass_list = []
    for dictq in data:
        ass_list.append(dictq['assignee_standardized'])
    top_ten_ass = PatentData.objects.filter(assignee_standardized__in=ass_list).order_by('assignee_standardized')
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
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        df.to_excel(response, index=False, sheet_name='Top Ten Cited Patents')
        return response


def top_ten_cpc_exl(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
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
    top_ten_cpc = PatentData.objects.filter(Q(cpc__in=cpc_keys_list)).order_by('cpc')
    if req.GET.get('display'):
        context = {
            'top_ten_cpc': top_ten_cpc,
        }
        return render(req, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            # 'Project Code': [patent.project_code for patent in top_ten_ass],
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
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        df.to_excel(response, index=False, sheet_name='Top Ten CPC')
        return response


def top_ten_ipc_exl(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
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
    top_ten_ipc = PatentData.objects.filter(cpc__in=ipc_keys_list)
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
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        df.to_excel(response, index=False, sheet_name='Top Ten IPC')
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
    response.write(output.getvalue())
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
def bibliographic_charts(req, chart_id):
    """
    Renders bibliographic charts based on the data provided in an uploaded Excel file.

    Args:
        req (HttpRequest): The HTTP request object.

    Returns:
        HttpResponse: Rendered response containing bibliographic charts.

    Example:
        The function reads an Excel file uploaded via POST, processes the data
        to generate various charts,
        and renders the 'bibliographic_charts.html' template with the generated data.

    Note:
        The function expects an Excel file with specific columns such as
        'Assignee - Standardized',
        'Earliest Patent Priority Date', 'Legal Status', 'Cited Patents - Count',
         'Citing Patents - Count', etc.

    """
    context = {}
    try:
        process_excel_data(context, req=req)
        user_instance = CustomUser.objects.get(id=req.session.get('logged_in_user_id'))
        context['user_instance'] = user_instance
        if req.method == 'POST':
            uploaded_media = req.FILES.get('patient_data')
            if uploaded_media:
                try:
                    first_row_project_code = pd.read_excel(uploaded_media).iloc[3, 18]
                    user_id = user_instance.id
                    file_content = uploaded_media.read()
                    # celery task
                    # process_excel_data_task.delay(user_id, first_row_project_code, file_content)
                    df = pd.read_excel(uploaded_media, engine='openpyxl')
                    patent_data_rows = []
                    user_instance = CustomUser.objects.get(id=user_id)
                    first_row_project_code = first_row_project_code
                    if PatentData.objects.filter(user_id=user_instance,
                                                 project_code=first_row_project_code):
                        PatentData.objects.filter(user_id=user_instance,
                                                  project_code=first_row_project_code).delete()
                    for index, row in df.iterrows():
                        # print(row['Priority Country'])
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
                            'project_code': first_row_project_code,
                            # 'priority_country': row['Priority Country']
                        }
                        patent_data_rows.append(patent_data_dict)
                    PatentData.objects.bulk_create([
                        PatentData(**data) for data in patent_data_rows
                    ])
                    process_excel_data(context, req=req)
                except Exception as e:
                    print(f"Error processing uploaded file: {str(e)}")
                    return HttpResponseServerError("Error processing uploaded file. Please try again.")
        return render(req, 'pages/charts/bibliographic_charts.html', context)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return HttpResponseServerError("An unexpected error occurred. Please try again.")


def process_excel_data(context, req):
    """
    Process the Excel data to generate various charts.

    Args:
        df (DataFrame): The DataFrame containing bibliographic data.
        context (dict): The context dictionary to store chart data.

    """

    user_id = req.session.get('logged_in_user_id')
    data = PatentData.objects.filter(user_id=user_id)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    # top recent assignees
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(user_id=user_id, application_dates__year__gte=last_five_years_start)
        .values('assignee_standardized')
        .annotate(count=Count('assignee_standardized'))
        .order_by('-count')[:10]
    )
    context.update({
        'recent_assignees_last_five_years': top_assignees_last_five_years,
        'top_assignees': process_assignees(req=req),
        'top_assignees_dict': data,
        'top_assignees_last_five_years': process_assignees_last_five_years(request=req),
        'legal_status_counts': get_legal_status_count(req),
        'top_cited_patents': get_top_cited_count(req),
        'top_citing_patents': get_top_citing_count(req),
        'year_wise_count': get_year_with_publication(req),
        'year_wise_exp_date': get_year_with_exp_date(req),
        'process_top_cited_patent': get_top_cited_count(req),
        'get_country_code_count': get_country_code_count(req),
        'get_country_code_counts_from_db': get_country_code_counts_from_db(req),
        'get_cpc_counts_from_db': get_cpc_counts_from_db(req),
        'get_ipc_counts': get_ipc_counts(req)
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


def get_country_code_count(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    assignee_country_counts_from_db = {}
    for patent_data in patent_data_queryset:
        assignee = patent_data.assignee_standardized
        publication_number = patent_data.publication_number
        country_code = publication_number[:2]
        if assignee not in assignee_country_counts_from_db:
            assignee_country_counts_from_db[assignee] = Counter()
        assignee_country_counts_from_db[assignee][country_code] += 1
    return assignee_country_counts_from_db


def get_ipc_counts(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    ipc_counts_from_db = Counter()

    for patent_data in patent_data_queryset:
        ipc_values = patent_data.ipc.split('|') if patent_data.ipc else []
        for ipc_value in ipc_values:
            ipc_code = ipc_value.strip()[:4]
            ipc_counts_from_db[ipc_code] += 1
    ipc_counts_dict_ws = dict(ipc_counts_from_db)
    sorted_ipc_counts = dict(sorted(ipc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    ipc_counts_dict = dict(list(sorted_ipc_counts.items())[:10])
    return ipc_counts_dict


def get_cpc_counts_from_db(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    cpc_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        cpc_values = patent_data.cpc.split('|') if patent_data.cpc else []
        for cpc_value in cpc_values:
            cpc_code = cpc_value.strip()[:4]
            cpc_counts_from_db[cpc_code] += 1
    cpc_counts_dict_ws = dict(cpc_counts_from_db)
    sorted_cpc_counts = dict(sorted(cpc_counts_dict_ws.items(), key=lambda item: item[1], reverse=True))
    cpc_counts_dict = dict(list(sorted_cpc_counts.items())[:10])
    req.session['cpc_counts_dict'] = cpc_counts_dict
    return cpc_counts_dict


def get_country_code_counts_from_db(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    country_code_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        publication_number = patent_data.publication_number
        country_code = publication_number[:2]
        country_code_counts_from_db[country_code] += 1
    country_code_counts_dict = dict(country_code_counts_from_db)
    return country_code_counts_dict


def get_legal_status_count(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    legal_status_counts = patent_data_queryset.values('legal_status').annotate(count=Count('legal_status'))
    legal_status_counts_dict = {item['legal_status']: item['count'] for item in legal_status_counts}
    all_legal_statuses = ['PENDING', 'EXPIRED', 'PCT', 'GRANTED']
    for legal_status in all_legal_statuses:
        legal_status_counts_dict.setdefault(legal_status, 0)
    return legal_status_counts_dict


def download_excel_file(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_cited_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]
    if request.GET.get('display'):
        context = {
            'top_ten_cited_patents': top_ten_cited_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            # 'Project Code': [patent.project_code for patent in top_ten_cited_patents],
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
        df.to_excel(response, index=False, sheet_name='Top Ten Cited Patents')
        return response


def download_citing_excel_file(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_citing_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-citing_patents_count')[:10]
    if request.GET.get('display'):
        context = {
            'top_ten_citing_patents': top_ten_citing_patents,
        }
        return render(request, 'pages/charts/top_ten_ipc.html', context)
    else:
        data = {
            # 'Project Code': [patent.project_code for patent in top_ten_cited_patents],
            'Publication Number': [patent.publication_number for patent in top_ten_citing_patents],
            'Assignee Standardized': [patent.assignee_standardized for patent in top_ten_citing_patents],
            'Cited Patents Count': [patent.cited_patents_count for patent in top_ten_citing_patents],
            'Legal Status': [patent.legal_status for patent in top_ten_citing_patents],
            'Application Dates': [patent.application_dates for patent in top_ten_citing_patents],
            'Publication Dates': [patent.publication_dates for patent in top_ten_citing_patents],
            'Application Number': [patent.application_number for patent in top_ten_citing_patents],
            'CPC Count': [patent.cpc for patent in top_ten_citing_patents],
            'IPC Count': [patent.ipc for patent in top_ten_citing_patents],
            'EFAN': [patent.e_fan for patent in top_ten_citing_patents],
        }
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
        df.to_excel(response, index=False, sheet_name='Top Ten Citing Patents')
        return response


def get_year_wise_excel(req):
    user_id = req.session.get('logged_in_user_id')
    year_counts = PatentData.objects.filter(user_id=user_id).annotate(
        publication_year=ExtractYear('publication_dates')
    ).values('publication_year').annotate(
        count=Count('id')
    ).order_by('-publication_year')

    data = {
        # 'Project Code': [patent.project_code for patent in year_wise_count],
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
    response['Content-Disposition'] = 'attachment; filename=top_ten_cited_patents.xlsx'
    df.to_excel(response, index=False, sheet_name='Top Ten Cited Patents')
    return response


def get_top_citing_count(req):
    citing_patents_dict = {}
    user_id_to_filter = req.session.get('logged_in_user_id')
    top_ten_citing_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        citing_patents_count__isnull=True
    ).order_by('-citing_patents_count')[:10]
    for patent_data in top_ten_citing_patents:
        citing_patents_dict[patent_data.publication_number] = {
            "count": patent_data.citing_patents_count,
            "assignee": patent_data.assignee_standardized
        }
    return citing_patents_dict


def get_top_cited_count(req):
    cited_patents_dict = {}
    user_id_to_filter = req.session.get('logged_in_user_id')
    top_ten_cited_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]
    for patent_data in top_ten_cited_patents:
        cited_patents_dict[patent_data.publication_number] = {
            "count": patent_data.cited_patents_count,
            "assignee": patent_data.assignee_standardized
        }
    # for patent_data in top_ten_cited_patents:
    #     cited_patents_dict[patent_data.publication_number] = patent_data.cited_patents_count
    return cited_patents_dict


def get_year_with_publication(req):
    user_id = req.session.get('logged_in_user_id')
    year_counts = PatentData.objects.filter(user_id=user_id).annotate(
        publication_year=ExtractYear('publication_dates')
    ).values('publication_year').annotate(
        count=Count('id')
    ).order_by('-publication_year')
    year_wise_count = {item['publication_year']: item['count'] for item in year_counts}
    return dict(year_wise_count)


def get_year_with_exp_date(req):
    user_id = req.session.get('logged_in_user_id')
    year_counts = PatentData.objects.filter(
        Q(expected_expiry_dates__isnull=False) | Q(expected_expiry_dates__isnull=True),
        expected_expiry_dates__isnull=False,
        user_id=user_id
    ).annotate(
        expected_expiry_date=ExtractYear('expected_expiry_dates')
    ).values('expected_expiry_date').annotate(count=Count('id'))
    year_wise_exp_date = {item['expected_expiry_date']: item['count'] for item in year_counts}
    return dict(year_wise_exp_date)


def process_assignees(req):
    """
    process_assignees
    """
    user_id = req.session.get('logged_in_user_id')
    data = PatentData.objects.filter(user_id=user_id)
    data = data.values('assignee_standardized').annotate(count=Count('assignee_standardized')).order_by('-count')[:10]
    result = [{'Assignee - Standardized': item['assignee_standardized'], 'count': item['count']} for item in data]
    return result


def process_assignees_last_five_years(request):
    user_id = request.session.get('logged_in_user_id')
    current_year = datetime.now().year
    last_five_years_start = current_year - 5
    top_assignees_last_five_years = (
        PatentData.objects
        .filter(user_id=user_id, application_dates__year__gte=last_five_years_start)
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
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
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
    return render(req, 'pages/onboard/profile.html', {'iebs_user': user_qs})
