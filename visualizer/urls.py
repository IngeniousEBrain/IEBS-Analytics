"""
URL patterns for the 'visualizer' app.
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.ie_analytics_home, name='login'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('forgot_password', views.forgot_password, name='forgot_password'),
    path('recover-password', views.recover_password, name='recover-password'),
    path('index', views.index, name='index'),
    path('profile', views.user_profile, name='profile'),
    path('bibliographic_charts/<int:chart_id>/', views.bibliographic_charts, name='bibliographic_charts'),
    path('project-list', views.project_list, name='project-list'),
    path('in_progress_project_list', views.in_progress_project_list, name='in_progress_project_list'),
    path('completed_project_list', views.completed_project_list, name='completed_project_list'),
    path('tech_charts', views.tech_charts, name='tech_charts'),
    path('competitor_charts', views.competitor_charts, name='competitor_charts'),
    path('download_excel_file/', views.download_excel_file, name='download_excel_file'),
    path('get_year_wise_excel/', views.get_year_wise_excel, name='get_year_wise_excel'),
]
