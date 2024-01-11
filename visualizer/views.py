from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from .models import CustomUser
from django.core.exceptions import ObjectDoesNotExist


def ie_analytics_home(request):
    """
    Render the home page.

    Parameters:
    - request: HTTP request object

    Returns:
    - Rendered template response
    """
    return render(request, 'pages/onboard/login.html')


def login(request):
    """
    Handle user login.
    
    Parameters:
    - request (HttpRequest): The HTTP request object containing login data.
    
    Returns:
    - JsonResponse: A JSON response indicating the login status.
    """

    if request.method == 'POST':
        username = request.POST.get('username')
        # project_code = request.POST.get('project_code')
        password = request.POST.get('password')
        if not all([username, password]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})
        try:
            user = CustomUser.objects.get(username=username)
            request.session['user_id'] = user.id
        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})

        if check_password(password, user.password):
            return JsonResponse({'status': 'success', 'redirect_url': '/index'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid username or password'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})


def forgot_password(request):
    """
    Handle the forgot password process.

    This function processes a POST request containing a username and project code, verifies their presence,
    checks if the provided combination exists in the database, and sets a session variable for password reset.

    Parameters:
    - request (HttpRequest): The HTTP request object containing forgot password data.

    Returns:
    - JsonResponse or HttpResponse: A JSON response or an HTML response indicating the status of the forgot password process.
      - If successful, the response includes a success status, an empty message, and a redirect URL to the password recovery page.
      - If unsuccessful (e.g., missing fields, invalid username or project code), the response includes an error status
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
    if request.method == 'POST':
        email = request.POST.get('email')
        print("emial**", email)
        if not all([email]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})
        try:
            user = CustomUser.objects.filter(email=email).first()
            if user:
                print(user)
                request.session['pass_reset_user_id'] = user.id
                return JsonResponse({'status': 'success', 'message': '', 'redirect_url': 'recover-password'})
            return JsonResponse({'status': 'error', 'message': 'user with this email does not exists.'})
        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Oops, Something went wrong, Please try again later.'})
    return render(request, 'pages/onboard/forgot-password.html')


def recover_password(request):
    """
       Handle the password recovery process.

       This function processes a POST request containing new password information, verifies the provided passwords,
       and updates the user's password securely using Django's set_password method.

       Parameters:
       - request (HttpRequest): The HTTP request object containing password recovery data.

       Returns:
       - JsonResponse: A JSON response indicating the status of the password recovery process.
         - If successful, the response includes a success status, a success message, and a redirect URL.
         - If unsuccessful (e.g., invalid user or session data, password mismatch), the response includes an error status
           and an appropriate error message.

       Example:
       Suppose the user submits a password recovery form with matching passwords.
       The function processes the request, updates the user's password, and returns a JSON response:
       {
           'status': 'success',
           'message': 'Password changed successfully. Please login to continue',
           'redirect_url': '/'
       }
    """
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if not all([password, confirm_password]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})

        try:
            user_id = request.session.get('pass_reset_user_id')
            user = CustomUser.objects.get(id=user_id)
            if confirm_password == password:
                # Use set_password to securely update the password
                user.set_password(confirm_password)
                user.save()
                return JsonResponse(
                    {'status': 'success', 'message': 'Password changed successfully. Please login to continue',
                     'redirect_url': '/'})
            else:
                return JsonResponse({'status': 'error', 'message': "Passwords don't match"})

        except ObjectDoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid user or session data.'})

    return render(request, 'pages/onboard/recover-password.html')


def index(request):
    """
  
    """
    return render(request, 'index.html')


def charts(request):
    """
    
    """
    return render(request, 'pages/charts/chartjs.html')


def widgets(request):
    """
    
    """
    return render(request, 'pages/widgets.html')


def techcharts(request):
    """
    
    """
    return render(request, 'tech_charts.html')
