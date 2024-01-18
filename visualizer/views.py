from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from .models import CustomUser, Project
from django.core.exceptions import ObjectDoesNotExist
from .packages import request
from django.contrib.sessions.models import Session
from django.utils import timezone
import pandas as pd
from datetime import datetime
from collections import Counter


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
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})
        try:
            user = CustomUser.objects.get(username=username, is_superuser=False)
            req.session['user_id'] = user.id
            req.session['user_name'] = username
        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})

        if check_password(password, user.password):
            return JsonResponse({'status': 'success', 'redirect_url': '/index'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})

    return render(req, 'pages/onboard/login.html')


def forgot_password(req):
    """
    Handle the forgot password process.

    This function processes a POST request containing a username and project code, verifies their presence,
    checks if the provided combination exists in the database, and sets a session variable for password reset.

    Parameters:
    - request (HttpRequest): The HTTP request object containing forgot password data.

    Returns:
    - JsonResponse or HttpResponse: A JSON response or an HTML response indicating the status of the forgot password
    process.
      - If successful, the response includes a success status, an empty message, and a redirect URL to the password
      recovery page.
      - If unsuccessful (e.g., missing fields, invalid username or project code), the response includes
       an error status
        and an appropriate error message.

    Example:
    Suppose the user submits a forgot password form with a valid username and project code.
    The function processes the request, sets a session variable for password reset, and returns a JSON response:
    {
        'status': 'success',
        'message': '',
        'redirect_url': 'recover-password'
    }
    """
    if req.method == 'POST':
        email = req.POST.get('email')
        if not all([email]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})
        try:
            user = CustomUser.objects.filter(email=email).first()
            if user:
                req.session['pass_reset_user_id'] = user.id
                return JsonResponse({'status': 'success', 'message': '', 'redirect_url': 'recover-password'})
            return JsonResponse({'status': 'error', 'message': 'user with this email does not exists.'})
        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Oops, Something went wrong, Please try again later.'})
    return render(req, 'pages/onboard/forgot-password.html')


def recover_password(req):
    """
       Handle the password recovery process.

       This function processes a POST request containing new password information, verifies the provided passwords,
       and updates the user's password securely using Django's set_password method.

       Parameters:
       - request (HttpRequest): The HTTP request object containing password recovery data.

       Returns:
       - JsonResponse: A JSON response indicating the status of the password recovery process.
         - If successful, the response includes a success status, a success message, and a redirect URL.
         - If unsuccessful (e.g., invalid user or session data, password mismatch), the response includes an error
          status
           and an appropriate error message.

       Example:
       Suppose the user submits a password recovery form with matching passwords.
       The function processes the request, updates the user's password, and returns a JSON response:
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
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})

        try:
            user_id = req.session.get('pass_reset_user_id')
            user = CustomUser.objects.get(id=user_id)
            if confirm_password == password:
                user.set_password(confirm_password)
                user.save()
                return JsonResponse(
                    {'status': 'success', 'message': 'Password changed successfully. Please login to continue',
                     'redirect_url': '/'})
            else:
                return JsonResponse({'status': 'error', 'message': "Passwords don't match"})
        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid user or session data.'})
    return render(req, 'pages/onboard/recover-password.html')


@request.validator
def index(req):
    """
  
    """
    context = {}
    if 'user_id' in req.session:
        user_id = req.session.get('user_id')
        user_qs = CustomUser.objects.filter(id=user_id).first()
        total = Project.objects.filter(userprojectassociation__user_id=user_id)
        completed_projects = Project.objects.filter(
            userprojectassociation__user_id=user_id, status__exact='Completed'
        )
        in_progress_projects = Project.objects.filter(
            userprojectassociation__user_id=user_id, status__exact='In Progress'
        )

        context = {
            'user': user_qs,
            'total': total,
            'completed_projects': completed_projects,
            'in_progress_projects': in_progress_projects,
        }
    return render(req, 'index.html', context)


@request.validator
def project_list(req):
    user_id = req.session.get('user_id')
    user_qs = CustomUser.objects.get(id=user_id)
    projects = Project.objects.filter(userprojectassociation__user_id=user_id)
    context = {'projects_data': projects, 'user_qs': user_qs}
    return render(req, 'pages/projects/project_listing.html', context)


@request.validator
def bibliographic_charts(req):
    context = {}
    if req.method == 'POST':
        uploaded_media = req.FILES.get('patient_data')
        if uploaded_media:
            try:
                df = pd.read_excel(uploaded_media)
                df['Assignee - Standardized'] = df['Assignee - Standardized'].str.lower()
                top_assignees = df['Assignee - Standardized'].value_counts().head(10)
                df['Year'] = pd.to_datetime(df['Earliest Patent Priority Date']).dt.year
                legal_status_counts = df['Legal Status'].value_counts()

                pending_count = legal_status_counts.get('PENDING', 0)
                expired_count = legal_status_counts.get('EXPIRED', 0)
                pct_count = legal_status_counts.get('PCT', 0)
                granted_count = legal_status_counts.get('GRANTED', 0)

                cited_patents_counts = df.groupby('Publication Number')['Cited Patents - Count'].sum()
                top_cited_patents = cited_patents_counts.sort_values(ascending=False).head(10).reset_index()

                citing_patents_count = df.groupby('Publication Number')['Citing Patents - Count'].sum()
                top_citing_patents = citing_patents_count.sort_values(ascending=False).head(10).reset_index()

                last_five_years = range(datetime.now().year - 4, datetime.now().year + 1)
                filtered_data = df[df['Year'].isin(last_five_years)]
                top_assignees_last_five_years = filtered_data['Assignee - Standardized'].value_counts().head(10)
                top_assignees_last_five_years_list = top_assignees_last_five_years.reset_index().to_dict(
                    orient='records')

                top_assignees_list = top_assignees.reset_index().to_dict(orient='records')
                top_cited_patents_dict = top_cited_patents.set_index('Publication Number')[
                    'Cited Patents - Count'].to_dict()
                top_citing_patents_dict = top_citing_patents.set_index('Publication Number')[
                    'Citing Patents - Count'].to_dict()

                publication_dates = pd.to_datetime(df['Publication Dates'])
                year_wise_count = Counter(publication_dates.dt.year)

                # year_wise_exp_date
                expected_exp_date = pd.to_datetime(df['Expected Expiry Dates'])
                year_wise_exp_date = Counter(expected_exp_date.dt.year.dropna())

                df['Country Code'] = df['Publication Number'].str[:2]

                # Count occurrences of each country code
                country_code_counts = df['Country Code'].value_counts().to_dict()

                # Include country code counts in the context
                context['country_code_counts'] = country_code_counts

                assignee_country_counts = {}
                for _, row in df.iterrows():
                    assignee = row['Assignee - Standardized']
                    country_code = row['Country Code']

                    # Create a dictionary for the assignee if not present
                    if assignee not in assignee_country_counts:
                        assignee_country_counts[assignee] = Counter()

                    # Increment the count for the country code
                    assignee_country_counts[assignee][country_code] += 1

                # Include assignee_country_counts in the context
                context['assignee_country_counts'] = {
                    assignee: dict(counts) for assignee, counts in assignee_country_counts.items()
                }

                cpc_counts = Counter()
                for _, row in df.iterrows():
                    cpc_values = str(row['CPC']).replace(' ', '').split('|')
                    for cpc_value in cpc_values:
                        # Take the first four characters and increment the count
                        cpc_code = cpc_value[:4]
                        cpc_counts[cpc_code] += 1
                context['cpc_counts'] = dict(cpc_counts)

                ipc_counts = Counter()
                for _, row in df.iterrows():
                    ipc_values = str(row['IPC']).replace(' ', '').split('|')
                    for ipc_value in ipc_values:
                        # Take the first four characters and increment the count
                        ipc_code = ipc_value[:4]
                        ipc_counts[ipc_code] += 1
                context['ipc_counts'] = dict(ipc_counts)

                assignee_legal_status_counts = {}
                for _, row in df.iterrows():
                    assignee = row['Assignee - Standardized']
                    legal_status = row['Legal Status']

                    # Create a dictionary for the assignee if not present
                    if assignee not in assignee_legal_status_counts:
                        assignee_legal_status_counts[assignee] = Counter()

                    # Increment the count for the legal status
                    assignee_legal_status_counts[assignee][legal_status] += 1

                # Include assignee_legal_status_counts in the context

                cpc_assignee_counts = {}
                for _, row in df.iterrows():
                    cpc_values = str(row['CPC']).replace(' ', '').split('|')
                    assignee = row['Assignee - Standardized']
                    for cpc_value in cpc_values:
                        # Take the first four characters of the CPC code
                        cpc_code = cpc_value[:4]

                        # Create a dictionary for the CPC code if not present
                        if cpc_code not in cpc_assignee_counts:
                            cpc_assignee_counts[cpc_code] = Counter()

                        # Increment the count for the Assignee - Standardized
                        cpc_assignee_counts[cpc_code][assignee] += 1

                # Include cpc_assignee_counts in the context
                context['cpc_assignee_counts'] = {
                    cpc_code: dict(assignee_counts) for cpc_code, assignee_counts in cpc_assignee_counts.items()
                }
                # print("cpc_assignee_counts:", context['cpc_assignee_counts'])

                # print("cpc_counts:", context['cpc_counts'])
                # print("assignee_wise_jurisdiction:",context['assignee_country_counts'])
                # print("country_code_counts:",context['country_code_counts'])

                context = {
                    'assignee_legal_status_counts': {
                        assignee: dict(status_counts) for assignee, status_counts in
                        assignee_legal_status_counts.items()
                    },
                    'ipc_counts': ipc_counts,
                    'cpc_counts': cpc_counts,
                    'top_assignees': top_assignees_list,
                    'top_assignees_last_five_years': top_assignees_last_five_years_list,
                    'legal_status_counts': {
                        'PENDING': pending_count,
                        'EXPIRED': expired_count,
                        'PCT': pct_count,
                        'GRANTED': granted_count
                    },
                    'top_cited_patents': top_cited_patents_dict,
                    'top_citing_patents': top_citing_patents_dict,
                    'year_wise_count': dict(year_wise_count),
                    'year_wise_exp_date': dict(year_wise_exp_date)
                }
            except pd.errors.ParserError as e:
                print("Error parsing Excel file:", str(e))
    return render(req, 'pages/charts/bibliographic_charts.html', context)


@request.validator
def tech_charts(req):
    """
    
    """
    return render(req, 'tech_charts.html')


@request.validator
def logout():
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    for session in sessions:
        session.delete()
        return redirect('login')


@request.validator
def user_profile(req):
    user_id = req.session.get('user_id')
    user_qs = CustomUser.objects.get(id=user_id)
    return render(req, 'pages/onboard/profile.html', {'iebs_user': user_qs})


def base(req):
    user_id = req.session.get('userId')
    user_qs = CustomUser.objects.get(id=user_id)
    return render(req, 'base.html', {'iebs_user': user_qs})
