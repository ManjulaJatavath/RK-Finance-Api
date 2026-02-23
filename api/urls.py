from django.urls import path
from . import views

urlpatterns = [

    # ========================================
    # AUTH ENDPOINTS
    # ========================================
    path("sign-in/", views.SignUpEndpoint.as_view()),
    path("login/", views.loginEndpoint.as_view()),
    path('logout', views.LogoutEndpoint.as_view(), name='logout'),
    path('send-otp/', views.SendOTPEndpoint.as_view(), name='send_otp'),
    path('verify-otp/', views.VerifyOTPEndpoint.as_view(), name='verify_otp'),
    path('auth/refresh-token/', views.RefreshTokenEndpoint.as_view(), name='refresh_token'),

    # ========================================
    # USER ENDPOINTS
    # ========================================
    path('users-create/', views.UserListEndpoint.as_view()),
    path('users-create/<int:pk>/', views.UserDetailEndpoint.as_view()),
    path('users-create/', views.UserCreateEndpoint.as_view(), name='create_user'),
    path('users-create/<int:pk>/', views.UserUpdateEndpoint.as_view(), name='update_user'),
    path('users-create/<int:user_id>/delete/', views.UserDeleteEndpoint.as_view(), name='delete_user'),

    # ========================================
    # NOTIFICATION ENDPOINTS
    # ========================================
    path('send-notification/', views.NotificationEndpoint.as_view(), name='send_notification'),
    path('send-notification/<int:notification_id>/read/', views.MarkNotificationReadEndpoint.as_view(), name='mark_notification_read'),
    path('send-notification/<int:notification_id>/', views.DeleteNotificationEndpoint.as_view(), name='delete_notification'),

    # ========================================
    # LOAN APPLICATION ENDPOINTS
    # ========================================
    path('loan-applications', views.LoanApplicationEndpoint.as_view(), name='loan_applications'),
    path('loan-applications/stats/summary/', views.LoanStatisticsEndpoint.as_view(), name='get_loan_statistics'),
    path('dashboard/stats/', views.DashboardStatsEndpoint.as_view(), name='get_dashboard_stats'),
    path('loan-applications/<int:loan_id>', views.LoanApplicationDetailEndpoint.as_view(), name='get_loan_application'),
    path('loan-applications/<int:loan_id>/status', views.LoanStatusEndpoint.as_view(), name='update_loan_status'),

    # ========================================
    # AGREEMENT ENDPOINTS  ← MISSING ONES ADDED
    # ========================================
    path('upload/', views.UploadTemplateEndpoint.as_view(), name='upload_template'),
    path('agreements/create/', views.AgreementCreateEndpoint.as_view(), name='agreement_create'),
    path('agreements/get-sign-url/<int:agreement_id>/', views.AgreementSignUrlEndpoint.as_view(), name='agreement_sign_url'),
    path('agreements/submit-signature/<int:agreement_id>/', views.AgreementSubmitSignatureEndpoint.as_view(), name='agreement_submit_signature'),
    
    # ══════════════════════════════════════════════════════════════════════════
    # GOLD LOAN APPLICATIONS
    # ══════════════════════════════════════════════════════════════════════════
    path(
        'gold-loan/applications',
        views.GoldLoanApplicationEndpoint.as_view(),
        name='gold_loan_applications',
    ),
    path(
        'gold-loan/applications/<int:pk>/',
        views.GoldLoanApplicationDetailEndpoint.as_view(),
        name='gold_loan_application_detail',
    ),

    path("gold-rate/", views.GoldRateEndpoint.as_view(), name="gold-rate"),

    # ══════════════════════════════════════════════════════════════════════════
    # ADMIN ACTIONS
    # ══════════════════════════════════════════════════════════════════════════

    path(
        'gold-loan/applications/<int:pk>/approval/',
        views.GoldLoanApprovalEndpoint.as_view(),
        name='gold_loan_application_approval',
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # PLEDGED ORNAMENTS
    # ══════════════════════════════════════════════════════════════════════════
    path(
        'gold-loan/applications/<int:pk>/pledged-ornaments/',
        views.PledgedOrnamentsListEndpoint.as_view(),
        name='gold_loan_pledged_ornaments',
    ),

    # ══════════════════════════════════════════════════════════════════════════
    # STATISTICS & DASHBOARD
    # ══════════════════════════════════════════════════════════════════════════
    path(
        'gold-loan/dashboard/stats/',
        views.GoldLoanDashboardStatsEndpoint.as_view(),
        name='gold_loan_dashboard_stats',
    ),
]