from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from .models import CustomUser  # Import your CustomUser model here

def IeAnalyticshome(request):
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
        project_code = request.POST.get('project_code')
        password = request.POST.get('password')    
        if not all([username, password, project_code]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'})
       
        try:
            user = CustomUser.objects.get(username=username, project_code__code=project_code) 
            request.session['user_id'] = user.id
        except CustomUser.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid username, password, or project code.'})

        # Check password       
        if check_password(password, user.password):             
            return JsonResponse({'status': 'success', 'redirect_url': '/index'})

        return JsonResponse({'status': 'error', 'message': 'Invalid username, password, or project code.'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})



def forgot_password(request):
    """
    
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        project_code = request.POST.get('project_code')
        if not all([username, project_code]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'}) 
        try:
            user = CustomUser.objects.get(username=username, project_code__code=project_code) 
            if user:
                request.session['pass_reset_user_id'] = user.id
                return redirect('recover-password')
        except CustomUser.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid username, password, or project code.'})
        
    return render(request, 'pages/onboard/forgot-password.html')


def recover_password(request):
    """
    
    """  
    if request.method == 'POST':       
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if not all([password, confirm_password]):
            return JsonResponse({'status': 'error', 'message': 'Please insert all the required fields'}) 
        try:
            if confirm_password == password:                   
                user_id = request.session.get('pass_reset_user_id')
                print("matched",user_id)
                user=CustomUser.objects.filter(id=user_id).first()
                print(user)
                user.set_password(confirm_password)
                user.save()
                return render(request, 'pages/onboard/login.html')
            return JsonResponse({'status': 'error', 'message': "Password Does't Match'"})
        except CustomUser.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid username, password, or project code.'})
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

# def chart_data(request):
#     """

#     """
#     data = {
#         'labels': ['January', 'February', 'March', 'April', 'May'],
#         'values': [40, 20, 30, 80, 50]
#     }
#     return JsonResponse(data)


def chart_view(request):
    """

    """
    return render(request, 'chart.html')
