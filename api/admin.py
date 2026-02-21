from django.contrib import admin
from .models import User, Notification, Agreement, LoanApplication, LoanPayment


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'first_name', 'last_name', 'mobile_number', 'role', 'is_active']
    list_filter = ['role', 'is_active', 'created_at']
    search_fields = ['email', 'first_name', 'last_name', 'mobile_number']
    ordering = ['-id']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'title', 'read', 'created_at']
    list_filter = ['read', 'created_at']
    search_fields = ['title', 'summary', 'user__email']
    ordering = ['-id']


@admin.register(Agreement)
class AgreementAdmin(admin.ModelAdmin):
    list_display = ['id', 'user_name', 'user_phone', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['user_name', 'user_phone']
    ordering = ['-id']


@admin.register(LoanApplication)
class LoanApplicationAdmin(admin.ModelAdmin):
    list_display = ['id', 'applicant_name', 'user', 'loan_amount', 'status', 'created_at']
    list_filter = ['status', 'interest_type', 'tenure_type', 'created_at']
    search_fields = ['applicant_name', 'mobile_number', 'email_id', 'aadhaar_number']
    ordering = ['-created_at']


@admin.register(LoanPayment)
class LoanPaymentAdmin(admin.ModelAdmin):
    list_display = ['id', 'loan_application', 'payment_number', 'payment_amount', 'status', 'due_date']
    list_filter = ['status', 'due_date', 'created_at']
    search_fields = ['loan_application__applicant_name']
    ordering = ['loan_application', 'payment_number']