from django.urls import path
from . import views

urlpatterns = [
    path('',views.IeAnalyticshome,name='login'),
    path('login',views.login,name='login'),
    path('forgot_password',views.forgot_password,name='forgot_password'),
    path('recover-password',views.recover_password,name='recover-password'),
    path('index',views.index, name='index'),
    path('charts',views.charts, name='charts'),
    path('widgets', views.widgets, name='widgets'),
    path('tech-charts',views.techcharts, name='tech_charts'),
]
