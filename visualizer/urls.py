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
    path('project_client_association/', views.project_client_association, name='project_client_association'),
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
    path('download_innovative_exl/<str:country>/<str:project_id>/', views.download_innovative_exl,
         name='download_innovative_exl'),
    path('download_top_assignee_exl/<str:assignee>/<str:project_id>/', views.download_top_assignee_exl,
         name='download_top_assignee_exl'),
    path('download_recent_assignee_exl/<str:assignee>/<str:project_id>/', views.download_recent_assignee_exl,
         name='download_recent_assignee_exl'),
    path('download_legal_status_exl/<str:status>/<str:project_id>/', views.download_legal_status_exl,
         name='download_legal_status_exl'),
    path('download_publication_exl/<str:year>/<str:project_id>/', views.download_publication_exl,
         name='download_publication_exl'),
    path('download_exp_exl/<str:year>/<str:project_id>/', views.download_exp_exl, name='download_exp_exl'),
    path('download_excel/', views.download_excel_view, name='download_excel'),
    path('fetch_data/', views.fetch_data_view, name='fetch_data'),
    # ==========================competitive chart data===========================================
    path('competitor_colab_view/<str:proj_code>/', views.competitor_colab_view, name='competitor_colab_view'),
    path('get_associated_projects/', views.get_associated_projects, name='get_associated_projects'),
    path('doc_upload/<int:project_id>/', views.doc_upload, name='doc_upload'),
    path('download_file/<int:project_id>/', views.download_file, name='download_file'),

    #     NEW ADMIN PORTAL

    path('admin_login/', views.admin_login, name='admin_login'),
    path('admin_profile/', views.admin_profile, name='admin_profile'),
    path('admin_index/', views.admin_index, name='admin_index'),
    path('add_project/', views.add_project, name='add_project'),
    path('add_user/', views.add_user, name='add_user'),
    path('edit_user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('delete_user/', views.delete_user, name='delete_user'),
    path('user_listing/', views.user_listing, name='user_listing'),
    path('reports_listing/<int:project_id>/', views.reports_listing, name='reports_listing'),
    path('delete_report/<int:file_id>/', views.delete_report, name='delete_report'),
    path('user_project_association/', views.user_project_association, name='user_project_association'),
    path('admin_project_listing/', views.admin_project_listing, name='admin_project_listing'),
    path('admin_completed_projects/', views.admin_completed_projects, name='admin_completed_projects'),
    path('admin_in_progress_projects/', views.admin_in_progress_projects, name='admin_in_progress_projects'),
    path('get_associated_users/<int:project_id>/', views.get_associated_users, name='get_associated_users'),
    path('association_listing/<int:project_id>/', views.association_listing, name='association_listing'),
    path('associate_users_with_project/', views.associate_users_with_project, name='associate_users_with_project'),
    path('delete_project_by_admin/', views.delete_project_by_admin, name='delete_project_by_admin'),
    path('deallocate_users_ajax/', views.deallocate_users_ajax, name='deallocate_users_ajax'),
]
