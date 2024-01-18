from django.urls import path
from . import views

urlpatterns = [
    path('', views.ie_analytics_home, name='login'),
    path('login', views.login, name='login'),
    path('forgot_password', views.forgot_password, name='forgot_password'),
    path('recover-password', views.recover_password, name='recover-password'),
    path('index', views.index, name='index'),
    path('profile', views.user_profile, name='profile'),
    path('bibliographic_charts', views.bibliographic_charts, name='bibliographic_charts'),
    path('project-list', views.project_list, name='project-list'),
    path('tech-charts', views.tech_charts, name='tech-charts'),
]
