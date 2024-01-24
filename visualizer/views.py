"""
Views for the 'visualizer' app.
"""
# Third-party imports
from datetime import datetime
from collections import Counter
import pandas as pd
import io
import math

# Django imports
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.http import HttpResponse
# Local imports
from .models import CustomUser, Project, PatentData
from .packages import request


# from django.db.models import Q
# import json


def ie_analytics_home(req):
    """
    Render the home page.

    Parameters:
    - request: HTTP request object

    Returns:
    - Rendered template response
    """
    return render(req, 'pages/onboard/login.html')


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
    if 'user_id' in req.session:
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


def handle_nat(dt):
    if pd.isna(dt):
        return None
    else:
        return dt


@request.validator
def bibliographic_charts(req):
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
    if req.method == 'POST':
        uploaded_media = req.FILES.get('patient_data')
        if uploaded_media:
            try:
                df = pd.read_excel(uploaded_media)
                process_excel_data(df, context)
                user_instance = CustomUser.objects.get(id=req.session.get('logged_in_user_id'))
                # PatentData.objects.filter(user_id=user_instance)
                patent_data_rows = []
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
                    earliest_patent_priority_date = pd.NaT if pd.isna(earliest_patent_priority_str) else pd.to_datetime(
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
                        'e_fan': row['EFAN']
                    }
                    patent_data_rows.append(patent_data_dict)
                PatentData.objects.bulk_create([
                    PatentData(**data) for data in patent_data_rows
                ])

            except pd.errors.ParserError as e:
                print("Error parsing Excel file:", str(e))
            except ValidationError as e:
                print("Validation Error:", str(e))

    return render(req, 'pages/charts/bibliographic_charts.html', context)


def process_excel_data(df, context):
    """
    Process the Excel data to generate various charts.

    Args:
        df (DataFrame): The DataFrame containing bibliographic data.
        context (dict): The context dictionary to store chart data.

    """
    df['Assignee - Standardized'] = df['Assignee - Standardized'].str.lower()
    df['Year'] = pd.to_datetime(df['Earliest Patent Priority Date']).dt.year
    citing_patents_count = df.groupby('Publication Number')['Citing Patents - Count'].sum()
    top_citing_patents = citing_patents_count.sort_values(ascending=False).head(10).reset_index()
    last_five_years = range(datetime.now().year - 4, datetime.now().year + 1)
    filtered_data = df[df['Year'].isin(last_five_years)]
    top_assignees_last_five_years = (
        filtered_data['Assignee - Standardized']
        .value_counts()
        .head(10)
    )
    top_assignees_last_five_years_list = (
        top_assignees_last_five_years
        .reset_index()
        .to_dict(orient='records')
    )

    top_citing_patents_dict = (
        top_citing_patents
        .set_index('Publication Number')['Citing Patents - Count']
        .to_dict()
    )

    publication_dates = pd.to_datetime(df['Publication Dates'])
    year_wise_count = Counter(publication_dates.dt.year)

    expected_exp_date = pd.to_datetime(df['Expected Expiry Dates'])
    year_wise_exp_date = Counter(expected_exp_date.dt.year.dropna())

    df['Country Code'] = df['Publication Number'].str[:2]
    top_assignees = process_assignees(df)
    context.update({
        'top_assignees': top_assignees,
        'top_assignees_last_five_years': top_assignees_last_five_years_list,
        'legal_status_counts': process_legal_status(df),
        'top_cited_patents': process_top_cited_patent(df),
        'top_citing_patents': top_citing_patents_dict,
        'year_wise_count': dict(year_wise_count),
        'year_wise_exp_date': dict(year_wise_exp_date),
        'process_top_cited_patent': process_top_cited_patent(df)

    })

    assignee_country_counts = {}
    for _, row in df.iterrows():
        assignee = row['Assignee - Standardized']
        country_code = row['Country Code']
        if assignee not in assignee_country_counts:
            assignee_country_counts[assignee] = Counter()
        assignee_country_counts[assignee][country_code] += 1
    context['assignee_country_counts'] = {assignee: dict(counts) for assignee, counts in
                                          assignee_country_counts.items()}

    cpc_counts = Counter()
    ipc_counts = Counter()
    for _, row in df.iterrows():
        cpc_values = str(row['CPC']).replace(' ', '').split('|')
        ipc_values = str(row['IPC']).replace(' ', '').split('|')

        for cpc_value in cpc_values:
            cpc_code = cpc_value[:4]
            cpc_counts[cpc_code] += 1

        for ipc_value in ipc_values:
            ipc_code = ipc_value[:4]
            ipc_counts[ipc_code] += 1

    context['cpc_counts'] = dict(cpc_counts)
    context['ipc_counts'] = dict(ipc_counts)

    assignee_legal_status_counts = {}
    cpc_assignee_counts = {}

    for _, row in df.iterrows():
        assignee = row['Assignee - Standardized']
        legal_status = row['Legal Status']
        if assignee not in assignee_legal_status_counts:
            assignee_legal_status_counts[assignee] = Counter()
        assignee_legal_status_counts[assignee][legal_status] += 1

        cpc_values = str(row['CPC']).replace(' ', '').split('|')
        for cpc_value in cpc_values:
            cpc_code = cpc_value[:4]

            if cpc_code not in cpc_assignee_counts:
                cpc_assignee_counts[cpc_code] = Counter()
            cpc_assignee_counts[cpc_code][assignee] += 1

    context['assignee_legal_status_counts'] = {
        assignee: dict(status_counts) for assignee, status_counts in
        assignee_legal_status_counts.items()
    }
    context['cpc_assignee_counts'] = {
        cpc_code: dict(assignee_counts) for cpc_code, assignee_counts in
        cpc_assignee_counts.items()
    }


def process_assignees(df):
    """
    process_assignees

    """
    df['Assignee - Standardized'] = df['Assignee - Standardized'].str.lower()
    top_assignees = df['Assignee - Standardized'].value_counts().head(10)
    return top_assignees.reset_index().to_dict(orient='records')


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


def process_top_cited_patents(req):
    """
    Process top cited patents and find respective Assignee - Standardized.
    Return the result as an Excel file.
    """
    project_data = Project.objects.filter(user_id=req.session.get('logged_in_user_id'))

    pass


@request.validator
def tech_charts(req):
    """
    logic for tech charts
    """
    return render(req, 'tech_charts.html')


@request.validator
def logout():
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


def base(req):
    """
    Base.html
    """
    user_id = req.session.get('logged_in_user_id')
    user_qs = CustomUser.objects.get(id=user_id)
    return render(req, 'base.html', {'iebs_user': user_qs})
