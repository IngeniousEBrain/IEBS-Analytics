"""
Views for the 'visualizer' app.
"""
# Third-party imports
from datetime import datetime
import collections
from collections import Counter
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from django.db.models.functions import Substr
# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.http import HttpResponse
from django.http import HttpResponseServerError
from django.db.models.functions import ExtractYear
# Local imports
from .models import CustomUser, Project, PatentData
from .packages import request
from django.db.models import Count
from .tasks import process_excel_data_task
from django.views.decorators.csrf import csrf_exempt


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


@request.validator
def tech_charts(req):
    """
    logic for tech charts
    """
    return render(req, 'pages/charts/technical_chart.html')


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
        result[name]

        year_wise_count = PatentData.objects.filter(assignee_standardized=name).values(
            'application_dates__year').annotate(count=Count('id'))
        for data in year_wise_count:
            year = data['application_dates__year']
            count = data['count']
            result[name][year] = count
    return result


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
        title="Collaborations of competitors",
        xaxis=dict(title='Partners'),
        yaxis=dict(title='Assignees'),
        height=600,
        width=950,
    )
    div1 = fig1.to_html()
    result_b = get_top_assignees_by_year(req)
    # =====================================================================================
    data = []
    for assignee, yeardict in result_b.items():
        for year, count in yeardict.items():
            data.append({'Assignee': assignee.title(), 'Year': year, 'Count': count})
    df = pd.DataFrame(data)
    fig2 = px.scatter(df, x="Year", y="Assignee", size="Count",
                      size_max=100, title='Patent Count Bubble Chart')
    fig2.update_layout(
        xaxis_title='Application Year',
        yaxis_title='Assignee'
    )
    div2 = fig2.to_html(full_html=False)
    # =====================================================================================

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
    fig3 = make_subplots(rows=1, cols=2, shared_yaxes=True)
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
    fig3.update_layout(title_text='Parallel Horizontal Bar Charts')
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
    fig4.update_layout(barmode='stack', xaxis={'categoryorder': 'total descending'})
    div4 = fig4.to_html(full_html=False)
    # ===========================================================================

    patents = PatentData.objects.values('priority_country')
    print("FBRB:::", patents)
    df = px.data.gapminder().query("year==2007")
    fig6 = px.choropleth(df, locations="iso_alpha",
                         color="lifeExp",
                         hover_name="country",
                         color_continuous_scale=px.colors.sequential.Plasma)
    div6 = fig6.to_html(full_html=False)
    context = {'plot_div1': div1, 'plot_div2': div2, 'plot_div3': div3, 'plot_div4': div4,
               'plot_div6': div6}
    return render(req, 'pages/charts/competitor_charts.html', context)


def handle_nat(dt):
    if pd.isna(dt):
        return None
    else:
        return dt


import math


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
                    # # celery task
                    df = pd.read_excel(uploaded_media, engine='openpyxl')
                    patent_data_rows = []
                    user_instance = CustomUser.objects.get(id=user_id)
                    first_row_project_code = first_row_project_code
                    if PatentData.objects.filter(user_id=user_instance,
                                                 project_code=first_row_project_code):
                        PatentData.objects.filter(user_id=user_instance,
                                                  project_code=first_row_project_code).delete()
                        print('deletion done')
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
                    # process_excel_data_task.delay(user_id, first_row_project_code, file_content)
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
    context.update({
        'top_assignees': process_assignees(req=req),
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
    ipc_counts_dict = dict(ipc_counts_from_db)
    return ipc_counts_dict


def get_cpc_counts_from_db(req):
    patent_data_queryset = PatentData.objects.filter(user_id=req.session.get('logged_in_user_id'))
    cpc_counts_from_db = Counter()
    for patent_data in patent_data_queryset:
        cpc_values = patent_data.cpc.split('|') if patent_data.cpc else []
        for cpc_value in cpc_values:
            cpc_code = cpc_value.strip()[:4]
            cpc_counts_from_db[cpc_code] += 1
    cpc_counts_dict = dict(cpc_counts_from_db)
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
    all_legal_statuses = ['PENDING', 'EXPIRED', 'PCT', 'GRANTED']  # Add other statuses if needed
    for legal_status in all_legal_statuses:
        legal_status_counts_dict.setdefault(legal_status, 0)
    return legal_status_counts_dict


def get_top_cited_count(req):
    cited_patents_dict = {}
    user_id_to_filter = req.session.get('logged_in_user_id')
    top_ten_cited_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]
    for patent_data in top_ten_cited_patents:
        cited_patents_dict[patent_data.publication_number] = patent_data.cited_patents_count
    return cited_patents_dict


def download_excel_file(request):
    user_id_to_filter = request.session.get('logged_in_user_id')
    top_ten_cited_patents = PatentData.objects.filter(
        user_id=user_id_to_filter
    ).exclude(
        cited_patents_count__isnull=True
    ).order_by('-cited_patents_count')[:10]
    data = {
        'Project Code': [patent.project_code for patent in top_ten_cited_patents],
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


def get_year_wise_excel(req):
    user_id = req.session.get('logged_in_user_id')
    year_counts = PatentData.objects.filter(user_id=user_id).annotate(
        publication_year=ExtractYear('publication_dates')
    ).values('publication_year').annotate(
        count=Count('id')
    ).order_by('-publication_year')
    year_wise_count = {item['publication_year']: item['count'] for item in year_counts}
    data = {
        'Project Code': [patent.project_code for patent in year_wise_count],
        'Publication Number': [patent.publication_number for patent in year_wise_count],
        'Assignee Standardized': [patent.assignee_standardized for patent in year_wise_count],
        'Cited Patents Count': [patent.cited_patents_count for patent in year_wise_count],
        'Legal Status': [patent.legal_status for patent in year_wise_count],
        'Application Dates': [patent.application_dates for patent in year_wise_count],
        'Publication Dates': [patent.publication_dates for patent in year_wise_count],
        'Application Number': [patent.application_number for patent in year_wise_count],
        'CPC Count': [patent.cpc for patent in year_wise_count],
        'IPC Count': [patent.ipc for patent in year_wise_count],
        'EFAN': [patent.e_fan for patent in year_wise_count],
        # Add other fields as needed
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
        citing_patents_dict[patent_data.publication_number] = patent_data.citing_patents_count
    return citing_patents_dict


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
    year_counts = PatentData.objects.filter(user_id=user_id).annotate(
        expected_expiry_date=ExtractYear('expected_expiry_dates')
    ).values('expected_expiry_date').annotate(
        count=Count('id')
    )
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
