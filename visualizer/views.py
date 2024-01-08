from django.shortcuts import render
from django.http import JsonResponse
from django.http import JsonResponse

def IeAnalyticshome(request):
    """
    Render the home page.

    Parameters:
    - request: HTTP request object

    Returns:
    - Rendered template response
    """
    return render(request, 'IeAnalyticshome.html')



def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        # project_code = request.POST.get('project_code')
        password = request.POST.get('password')        
        if username == 'iebs' and password == 'Pass@123':
            # Successful login
            return JsonResponse({'status': 'success', 'redirect_url': '/index'})
        
        # Failed login
        return JsonResponse({'status': 'error', 'message': 'Invalid username or password.'})




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

def chart_data(request):
    """

    """
    data = {
        'labels': ['January', 'February', 'March', 'April', 'May'],
        'values': [40, 20, 30, 80, 50]
    }
    return JsonResponse(data)


def chart_view(request):
    """

    """
    return render(request, 'chart.html')
