from django.urls import path
from . import views

urlpatterns = [
    path('chart-data/', views.chart_data, name='chart_data'),
    path('chart/', views.chart_view, name='chart_view'),
    path('',views.IeAnalyticshome,name='home'),
    path('login',views.login,name='login'),
    path('index',views.index, name='index'),
    path('charts',views.charts, name='charts'),
    path('widgets', views.widgets, name='widgets'),
    path('tech-charts',views.techcharts, name='tech_charts'),
]
