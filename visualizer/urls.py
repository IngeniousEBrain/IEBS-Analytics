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
    path('bibliographic_charts/<int:project_id>/', views.bibliographic_charts, name='bibliographic_charts'),
    # =================PROJECT ========================
    path('project-list/<str:chart_type>/', views.project_list, name='project-list'),
    path('delete_project/', views.delete_project, name='delete_project'),
    path('edit_project/<int:project_id>/', views.edit_project, name='edit_project'),
    # ================================================================
    path('in_progress_project_list', views.in_progress_project_list, name='in_progress_project_list'),
    path('completed_project_list', views.completed_project_list, name='completed_project_list'),
    path('tech_charts/<int:project_id>/', views.tech_charts, name='tech_charts'),
    path('competitor_charts/<int:project_id>/', views.competitor_charts, name='competitor_charts'),
    path('download_excel_file/<int:project_id>/', views.download_excel_file, name='download_excel_file'),
    path('download_citing_excel_file/<int:project_id>/', views.download_citing_excel_file,
         name='download_citing_excel_file'),
    path('download_citedExl/<int:project_id>/', views.download_citedExl, name='download_citedExl'),
    path('top_ten_ass_exl/<int:project_id>/', views.top_ten_ass_exl, name='top_ten_ass_exl'),
    path('top_ten_recent_ass_exl/<int:project_id>/', views.top_ten_recent_ass_exl, name='top_ten_recent_ass_exl'),
    path('get_year_wise_excel/<int:project_id>/', views.get_year_wise_excel, name='get_year_wise_excel'),
    path('download-demo-excel/', views.download_demo_excel, name='download_demo_excel'),
    path('top_ten_cpc_exl/<int:project_id>/', views.top_ten_cpc_exl, name='top_ten_cpc_exl'),
    path('top_ten_ipc_exl/<int:project_id>/', views.top_ten_ipc_exl, name='top_ten_ipc_exl'),
    path('download_ind_citing_excel/<str:patent>/<str:project_id>/', views.download_ind_citing_excel,
         name='download_ind_citing_excel'),
    path('download_ind_cited_excel/<str:patent>/<str:project_id>/', views.download_ind_cited_excel,
         name='download_ind_cited_excel'),
    path('individual_cpc_exl/<str:cpc>/<str:project_id>/', views.individual_cpc_exl, name='individual_cpc_exl'),
    path('individual_ipc_exl/<str:ipc>/<str:project_id>/', views.individual_ipc_exl, name='individual_ipc_exl'),
    path('download_innovative_exl/<str:country>/<str:project_id>/', views.download_innovative_exl, name='download_innovative_exl'),
    path('download_top_assignee_exl/<str:assignee>/<str:project_id>/', views.download_top_assignee_exl,
         name='download_top_assignee_exl'),
    path('download_recent_assignee_exl/<str:assignee>/<str:project_id>/', views.download_recent_assignee_exl,
         name='download_recent_assignee_exl'),
    path('download_legal_status_exl/<str:status>/<str:project_id>/', views.download_legal_status_exl, name='download_legal_status_exl'),
    path('download_publication_exl/<str:year>/<str:project_id>/', views.download_publication_exl, name='download_publication_exl'),
    path('download_exp_exl/<str:year>/<str:project_id>/', views.download_exp_exl, name='download_exp_exl'),
    path('download_excel/', views.download_excel_view, name='download_excel'),
    path('fetch_data/', views.fetch_data_view, name='fetch_data'),
    # ==========================competitive chart data===========================================
    path('competitor_colab_view/<str:proj_code>/', views.competitor_colab_view, name='competitor_colab_view'),

]
