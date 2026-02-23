import json
import uuid
from api.authentication import check_valid_email_address, check_valid_phone_number, get_tokens_for_user, validate_password

from api.paginator import BasePaginator
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .base import BaseAPIView
from django.conf import settings
from django.utils import timezone
from django.db import models
from .models import FDApplication, FDInterestPayout, FDInterestRateSlab, FDPayoutStatusChoices, FDStatusChoices, GoldLoanApplication, LoanStatusChoices, User, Notification, Agreement, LoanApplication, LoanPayment, calculate_fd_maturity, calculate_premature_closure, generate_payout_schedule
from .serializers import (
    FDApplicationAdminUpdateSerializer, FDApplicationCreateSerializer, FDApplicationDetailSerializer, FDApplicationListSerializer, FDCalculatorSerializer, FDInterestPayoutSerializer, FDInterestRateSlabSerializer, FDRenewSerializer, GoldLoanApplicationCreateSerializer, GoldLoanApplicationSerializer, MarkPaidSerializer, UserSerializer, UserCreateSerializer, NotificationSerializer,
    AgreementSerializer, LoanApplicationSerializer,
    LoanApplicationCreateSerializer, LoanPaymentSerializer
)
from django.db.models import Count, Sum
from .utils import (
    send_otp_via_twilio, generate_jwt_tokens, upload_to_supabase,
    convert_image_to_pdf, generate_signed_pdf
)
import jwt
from datetime import datetime, timedelta
import random
from django.db.models import Q
from django.contrib.auth.signals import user_logged_in
from sentry_sdk import capture_exception, capture_message
import requests
from bs4 import BeautifulSoup
from django.http import JsonResponse

otp_store = {}


# ========================================
# AUTH ENDPOINTS
# ========================================

class loginEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            medium = request.data.get("medium", False)
            password = request.data.get("password", False)
            if not password:
                capture_message("Sign in endpoint missing medium data")
                return Response(
                    {"error": "Something went wrong. Please try again later or contact the support team."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if medium == "email":
                if not request.data.get("email", False) or not check_valid_email_address(
                    request.data.get("email").strip().lower()
                ):
                    return Response(
                        {"error": "Please provide a valid email address."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                email = request.data.get("email").strip().lower()
                user = User.objects.get(email=email)

            elif medium == "mobile":
                if not request.data.get("mobile", False) or not check_valid_phone_number(
                    request.data.get("mobile").strip().lower()
                ):
                    return Response(
                        {"error": "Please provide a valid mobile number."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                mobile_number = request.data.get("mobile").strip().lower()
                user = User.objects.get(mobile_number=mobile_number)

            else:
                capture_message("Sign in endpoint wrong medium data")
                return Response(
                    {"error": "Something went wrong. Please try again later or contact the support team."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not user.check_password(password):
                return Response(
                    {"error": "Sorry, we could not find a user with the provided credentials. Please try again."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            if not user.is_active:
                return Response(
                    {"error": "Your account has been deactivated. Please contact your site administrator."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            serialized_user = UserCreateSerializer(user).data
            user.last_active = timezone.now()
            user.last_login_time = timezone.now()
            user.last_login_ip = request.META.get("REMOTE_ADDR")
            user.last_login_medium = medium
            user.last_login_uagent = request.META.get("HTTP_USER_AGENT")
            user.token_updated_at = timezone.now()
            user.save()

            access_token, refresh_token = get_tokens_for_user(user)
            return Response({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": serialized_user,
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response(
                {"error": "Sorry, we could not find a user with the provided credentials. Please try again."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            capture_exception(e)
            return Response(
                {"error": "Something went wrong. Please try again later or contact the support team."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SignUpEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            first_name = request.data.get("first_name", "User")
            last_name = request.data.get("last_name", "")
            mobile_number = request.data.get("mobile_number")
            email = request.data.get("email").strip().lower()
            password = request.data.get("password")

            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": "This email address is already taken. Please try another one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            is_valid_password, password_error = validate_password(password)
            if not is_valid_password:
                return Response({"error": password_error}, status=status.HTTP_400_BAD_REQUEST)

            username = uuid.uuid4().hex
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                mobile_number=mobile_number,
            )
            user.set_password(password)
            user.save()

            user_logged_in.send(
                sender=user, user=user,
                first_name=first_name, last_name=last_name,
                user_email=email, user_password=password,
            )

            serialized_user = UserSerializer(user).data
            access_token, refresh_token = get_tokens_for_user(user)
            return Response({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": serialized_user,
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            capture_exception(e)
            return Response(
                {"error": "Something went wrong. Please try again later or contact the support team.", "msg": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SendOTPEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        mobile_number = request.data.get('mobile_number')
        if not mobile_number:
            return Response({'message': 'Mobile number required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(mobile_number=mobile_number)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        otp = str(random.randint(100000, 999999))
        otp_store[mobile_number] = {
            'otp': otp,
            'expires_at': timezone.now() + timedelta(minutes=5)
        }

        success = send_otp_via_twilio(mobile_number, otp)
        if success:
            return Response({'message': 'OTP sent successfully'})
        return Response({'message': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        mobile_number = request.data.get('mobile_number')
        otp = request.data.get('otp')

        if not mobile_number or not otp:
            return Response({'message': 'Mobile number and OTP required'}, status=status.HTTP_400_BAD_REQUEST)

        record = otp_store.get(mobile_number)
        if not record:
            return Response({'message': 'OTP not found or expired'}, status=status.HTTP_400_BAD_REQUEST)

        if timezone.now() > record['expires_at']:
            del otp_store[mobile_number]
            return Response({'message': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        if record['otp'] != otp:
            return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        del otp_store[mobile_number]

        try:
            user = User.objects.get(mobile_number=mobile_number)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        tokens = generate_jwt_tokens(user)
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        })


class RefreshTokenEndpoint(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # 1. Matches your frontend payload { refresh_token: ... }
        refresh_token = request.data.get('refresh_token')
        
        if not refresh_token:
            return Response({'error': 'Refresh token missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 2. Ensure settings.SECRET_KEY is used if JWT_SECRET isn't defined
            secret = getattr(settings, 'JWT_SECRET', settings.SECRET_KEY)
            
            payload = jwt.decode(refresh_token, secret, algorithms=['HS256'])
            
            # 3. Check if 'id' or 'user_id' is the key in your payload
            user_id = payload.get('id') or payload.get('user_id')
            user = User.objects.get(id=user_id)
            
            tokens = generate_jwt_tokens(user)
            return Response({
                'access_token': tokens['access_token'],
                'refresh_token': tokens.get('refresh_token', refresh_token) # Return same or new refresh
            })

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            # 4. This prevents the 500 error by returning the actual error message
            return Response({'error': f'Server Error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutEndpoint(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response({'message': 'Logout successful'})


# ========================================
# USER ENDPOINTS
# ========================================

class UserListEndpoint(BaseAPIView, BasePaginator):
    model = User
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        search = request.GET.get('search', '')
        users = self.get_queryset()

        if search:
            users = users.filter(
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(email__icontains=search)
            )
        users = users.order_by('-id')

        return self.paginate(
            request,
            on_results=lambda results: self.serializer_class(results, many=True).data,
            queryset=users,
        )


class UserDetailEndpoint(BaseAPIView):
    model = User
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            user = User.objects.get(id=pk)
            return Response(self.serializer_class(user).data)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class UserCreateEndpoint(BaseAPIView, BasePaginator):
    model = User
    serializer_class = UserCreateSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        print(request.data, "request.data")
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'User created successfully',
                'user': UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateEndpoint(BaseAPIView):
    model = User
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        password = data.pop('password', None)
        serializer = self.serializer_class(user, data=data, partial=True)
        if serializer.is_valid():
            user = serializer.save()
            if password:
                user.set_password(password)
                user.save()
            return Response({
                'message': 'User updated successfully',
                'user': self.serializer_class(user).data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDeleteEndpoint(BaseAPIView):
    model = User
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({'message': 'User deleted successfully'})
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


# ========================================
# NOTIFICATION ENDPOINTS
# ========================================

class NotificationEndpoint(BaseAPIView):
    model = Notification
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        notifications = (
            self.get_queryset() if user.role == 'admin'
            else self.get_queryset().filter(user=user)
        )
        return Response(self.serializer_class(notifications, many=True).data)

    def post(self, request):
        user_id = request.data.get('user_id')
        title = request.data.get('title')
        summary = request.data.get('summary')

        if not user_id or not title or not summary:
            return Response({'message': 'user_id, title, summary required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        notification = Notification.objects.create(user=user, title=title, summary=summary)
        return Response(self.serializer_class(notification).data, status=status.HTTP_201_CREATED)


class MarkNotificationReadEndpoint(BaseAPIView):
    model = Notification
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id)
            notification.read = True
            notification.save()
            return Response(self.serializer_class(notification).data)
        except Notification.DoesNotExist:
            return Response({'message': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)


class DeleteNotificationEndpoint(BaseAPIView):
    model = Notification
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def delete(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id)
            notification.delete()
            return Response({'message': 'Notification deleted'})
        except Notification.DoesNotExist:
            return Response({'message': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)


# ========================================
# LOAN APPLICATION ENDPOINTS
# ========================================

class LoanApplicationEndpoint(BaseAPIView):
    model = LoanApplication
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        status_filter = request.GET.get('status')
        search = request.GET.get('search', '')
        page = int(request.GET.get('page', 1))
        limit = int(request.GET.get('limit', 10))
        sort_by = request.GET.get('sortBy', 'created_at')
        sort_order = request.GET.get('sortOrder', 'desc')

        loans = (
            self.get_queryset() if user.role == 'admin'
            else self.get_queryset().filter(user=user)
        )

        if status_filter:
            loans = loans.filter(status=status_filter)
        if search:
            loans = loans.filter(
                Q(applicant_name__icontains=search) |
                Q(mobile_number__icontains=search) |
                Q(email_id__icontains=search) |
                Q(aadhaar_number__icontains=search)
            )

        if sort_order == 'desc':
            sort_by = f'-{sort_by}'
        loans = loans.order_by(sort_by)

        total = loans.count()
        start = (page - 1) * limit
        loans = loans[start:start + limit]

        return Response({
            'success': True,
            'total': total,
            'page': page,
            'limit': limit,
            'totalPages': (total + limit - 1) // limit,
            'data': self.serializer_class(loans, many=True).data
        })

    def post(self, request):
        user = request.user
        photo_url = None
        print("RAW GENDER:", request.data.get("gender"))
        print("TYPE:", type(request.data.get("gender")))

        if 'photo' in request.FILES:
            photo_file = request.FILES['photo']
            file_name = f"loan_photos/{user.id}_{int(datetime.now().timestamp())}.png"
            photo_url = upload_to_supabase(photo_file.read(), file_name, photo_file.content_type)

        data = request.data.copy()
        data['user'] = user.id
        if photo_url:
            data['photo_url'] = photo_url

        serializer = LoanApplicationCreateSerializer(data=data)
        if serializer.is_valid():
            loan_application = serializer.save(user=user)
            Notification.objects.create(
                user=user,
                title='Loan Application Submitted',
                summary=f'Your loan application for ₹{loan_application.loan_amount} has been submitted successfully.'
            )
            return Response({
                'message': 'Loan application submitted successfully',
                'data': self.serializer_class(loan_application).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoanApplicationDetailEndpoint(BaseAPIView):
    model = LoanApplication
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, loan_id):
        try:
            loan = LoanApplication.objects.get(id=loan_id)
            if request.user.role != 'admin' and loan.user != request.user:
                return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
            return Response({'success': True, 'data': self.serializer_class(loan).data})
        except LoanApplication.DoesNotExist:
            return Response({'error': 'Loan application not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, loan_id):
        try:
            loan = LoanApplication.objects.get(id=loan_id)
            if request.user.role != 'admin' and loan.user != request.user:
                return Response(
                    {'error': 'You do not have permission to update this application'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = LoanApplicationCreateSerializer(loan, data=request.data, partial=True)
            if serializer.is_valid():
                loan = serializer.save()
                return Response({
                    'success': True,
                    'message': 'Loan application updated successfully',
                    'data': self.serializer_class(loan).data
                })
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except LoanApplication.DoesNotExist:
            return Response({'error': 'Loan application not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, loan_id):
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can delete loan applications'}, status=status.HTTP_403_FORBIDDEN)
        try:
            loan = LoanApplication.objects.get(id=loan_id)
            LoanPayment.objects.filter(loan_application=loan).delete()
            loan.delete()
            return Response({'success': True, 'message': 'Loan application deleted successfully'})
        except LoanApplication.DoesNotExist:
            return Response({'error': 'Loan application not found'}, status=status.HTTP_404_NOT_FOUND)


class LoanStatusEndpoint(BaseAPIView):
    model = LoanApplication
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request, loan_id):
        if request.user.role != 'admin':
            return Response({'error': 'Only admins can update loan status'}, status=status.HTTP_403_FORBIDDEN)

        new_status = request.data.get('status')
        valid_statuses = ['pending', 'approved', 'rejected', 'active', 'completed']
        if new_status not in valid_statuses:
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            loan = LoanApplication.objects.get(id=loan_id)
            loan.status = new_status
            loan.save()
            Notification.objects.create(
                user=loan.user,
                title=f'Loan Application {new_status.capitalize()}',
                summary=f'Your loan application for ₹{loan.loan_amount} has been {new_status}.'
            )
            return Response({
                'success': True,
                'message': f'Loan application status updated to {new_status}',
                'data': self.serializer_class(loan).data
            })
        except LoanApplication.DoesNotExist:
            return Response({'error': 'Loan application not found'}, status=status.HTTP_404_NOT_FOUND)


# ========================================
# STATS ENDPOINTS
# ========================================

class LoanStatisticsEndpoint(BaseAPIView):
    model = LoanApplication
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        loans = (
            self.get_queryset() if user.role == 'admin'
            else self.get_queryset().filter(user=user)
        )

        total_loan_amount = loans.aggregate(total=models.Sum('loan_amount'))['total'] or 0
        total_repayment = loans.aggregate(total=models.Sum('total_repayment_amount'))['total'] or 0

        return Response({
            'success': True,
            'data': {
                'totalApplications': loans.count(),
                'pendingApplications': loans.filter(status='pending').count(),
                'approvedApplications': loans.filter(status='approved').count(),
                'rejectedApplications': loans.filter(status='rejected').count(),
                'activeLoans': loans.filter(status='active').count(),
                'completedLoans': loans.filter(status='completed').count(),
                'totalLoanAmount': float(total_loan_amount),
                'totalRepaymentAmount': float(total_repayment)
            }
        })


class DashboardStatsEndpoint(BaseAPIView):
    model = LoanApplication
    serializer_class = LoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        loans = self.get_queryset()
        return Response({
            'success': True,
            'data': {
                'totalApplications': loans.count(),
                'activeCount': loans.filter(status='active').count(),
                'pendingCount': loans.filter(status='pending').count(),
                'approvedCount': loans.filter(status='approved').count(),
                'rejectedCount': loans.filter(status='rejected').count(),
                'completedCount': loans.filter(status='completed').count(),
            }
        })


# ========================================
# AGREEMENT ENDPOINTS
# ========================================

class UploadTemplateEndpoint(BaseAPIView):
    model = Agreement
    serializer_class = AgreementSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file = request.FILES.get('template')
        if not file:
            return Response({'message': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_url = upload_to_supabase(file.read(), f"templates/{file.name}", file.content_type)
            return Response({'message': 'Template uploaded successfully', 'url': file_url})
        except Exception as e:
            capture_exception(e)
            return Response({'message': 'Failed to upload template'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AgreementCreateEndpoint(BaseAPIView):
    model = Agreement
    serializer_class = AgreementSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user_phone = request.data.get('userPhone')
            template_url = request.data.get('templateUrl')
            user_name = request.data.get('userName')

            if not user_phone or not template_url or not user_name:
                return Response({'message': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

            agreement = Agreement.objects.create(
                template_url=template_url,
                user_name=user_name,
                user_phone=user_phone,
                status='pending'
            )

            signing_url = f"{settings.WEB_URL}/sign/{agreement.id}"

            from twilio.rest import Client
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            client.messages.create(
                from_='whatsapp:+14155238886',
                to=f'whatsapp:{user_phone}',
                body=f'Hello {user_name}, please sign your agreement here:\n{signing_url}'
            )

            return Response({
                'success': True,
                'message': 'Agreement created and link sent',
                'signingUrl': signing_url,
                'agreement': self.serializer_class(agreement).data
            })

        except Exception as e:
            capture_exception(e)
            return Response({'message': 'Failed to create agreement'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AgreementSignUrlEndpoint(BaseAPIView):
    model = Agreement
    serializer_class = AgreementSerializer
    permission_classes = [AllowAny]

    def get(self, request, agreement_id):
        try:
            agreement = Agreement.objects.get(id=agreement_id)
        except Agreement.DoesNotExist:
            return Response({'error': 'Agreement not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            from supabase import create_client
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
            bucket_name = settings.SUPABASE_BUCKET_NAME

            template_path = agreement.template_url
            supabase_prefix = f"{settings.SUPABASE_URL}/storage/v1/object/public/{bucket_name}/"
            if template_path.startswith(supabase_prefix):
                template_path = template_path.replace(supabase_prefix, '')

            result = supabase.storage.from_(bucket_name).create_signed_url(template_path, 120)
            if not result.get('signedURL'):
                return Response({'error': 'Could not generate PDF URL'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            signing_url = f"{settings.WEB_URL}/sign/{agreement_id}"
            return Response({'signingUrl': signing_url, 'pdfUrl': result['signedURL']})

        except Exception as e:
            capture_exception(e)
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AgreementSubmitSignatureEndpoint(BaseAPIView):
    model = Agreement
    serializer_class = AgreementSerializer
    permission_classes = [AllowAny]

    def post(self, request, agreement_id):
        try:
            signature = request.data.get('signature')
            template_url = request.data.get('templateUrl')

            if not signature or not template_url:
                return Response(
                    {'error': 'Signature and template URL are required.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            signed_pdf_buffer = generate_signed_pdf(signature, template_url)
            if not signed_pdf_buffer:
                return Response({'error': 'Failed to generate signed PDF'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            file_name = f"signed_agreements/{agreement_id}_signed.pdf"
            signed_pdf_url = upload_to_supabase(signed_pdf_buffer, file_name, 'application/pdf')

            if not signed_pdf_url:
                return Response({'error': 'Failed to upload signed PDF'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            agreement = Agreement.objects.get(id=agreement_id)
            agreement.status = 'signed'
            agreement.signed_pdf_url = signed_pdf_url
            agreement.signed_at = timezone.now()
            agreement.save()

            return Response({
                'message': 'Signature saved and PDF signed successfully',
                'signedPdfUrl': signed_pdf_url
            })

        except Agreement.DoesNotExist:
            return Response({'error': 'Agreement not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            capture_exception(e)
            return Response(
                {'error': 'Failed to process signature', 'msg': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            

# ──────────────────────────────────────────────────────────────────────────────
# GOLD LOAN APPLICATION — LIST + SUBMIT
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApplicationEndpoint(BaseAPIView):
    """
    GET  → List all gold loan applications.
           Admin sees all; applicant sees only their own.
           Supports: ?status= ?search= ?page= ?limit= ?sortBy= ?sortOrder=
    POST → Submit a new gold loan application with pledged ornament details.
    """
    model              = GoldLoanApplication
    serializer_class   = GoldLoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user          = request.user
        status_filter = request.GET.get('status')
        search        = request.GET.get('search', '').strip()
        page          = int(request.GET.get('page', 1))
        limit         = int(request.GET.get('limit', 10))
        sort_by       = request.GET.get('sortBy', 'created_at')
        sort_order    = request.GET.get('sortOrder', 'desc')

        gold_loans = (
            self.get_queryset()
            if user.role == 'admin'
            else self.get_queryset().filter(user=user)
        )

        if status_filter:
            gold_loans = gold_loans.filter(status=status_filter)

        if search:
            gold_loans = gold_loans.filter(
                Q(applicant_name__icontains=search)  |
                Q(mobile_number__icontains=search)   |
                Q(email_id__icontains=search)        |
                Q(aadhaar_number__icontains=search)
            )

        if sort_order == 'desc':
            sort_by = f'-{sort_by}'
        gold_loans = gold_loans.order_by(sort_by)

        total      = gold_loans.count()
        start      = (page - 1) * limit
        gold_loans = gold_loans.prefetch_related('pledged_ornaments')[start:start + limit]

        return Response({
            'success':    True,
            'total':      total,
            'page':       page,
            'limit':      limit,
            'totalPages': (total + limit - 1) // limit,
            'data':       self.serializer_class(gold_loans, many=True).data,
        })

    def post(self, request):
        user      = request.user
        photo_url = None

        if 'photo' in request.FILES:
            photo_file = request.FILES['photo']
            file_name  = f"gold_loan_photos/{user.id}_{int(datetime.now().timestamp())}.png"
            photo_url  = upload_to_supabase(
                photo_file.read(), file_name, photo_file.content_type
            )

        # ── Convert QueryDict to plain dict ───────────────────────────────────
        data = {key: request.data[key] for key in request.data}

        if photo_url:
            data['photo_url'] = photo_url

        # ── Fix field name mismatches ─────────────────────────────────────────
        if 'perm_area' in data:
            data['perm_area_village_town'] = data.pop('perm_area')
        if 'comm_area' in data:
            data['comm_area_village_town'] = data.pop('comm_area')
        if 'same_as_permanent' in data:
            data['comm_same_as_permanent'] = data.pop('same_as_permanent')

        # ── Parse gold_items JSON string ──────────────────────────────────────
        if 'gold_items' in data and isinstance(data['gold_items'], str):
            try:
                data['gold_items'] = json.loads(data['gold_items'])
            except (json.JSONDecodeError, ValueError):
                return Response({
                    'success': False,
                    'errors': {'gold_items': ['Invalid JSON format.']}
                }, status=status.HTTP_400_BAD_REQUEST)

        # ── Fix booleans ──────────────────────────────────────────────────────
        for bool_field in ['processing_fee_consent', 'declaration', 'terms_accepted', 'data_consent', 'comm_same_as_permanent']:
            if bool_field in data and isinstance(data[bool_field], str):
                data[bool_field] = data[bool_field].lower() in ('true', '1', 'yes')

        # ── Fix empty strings for integer and date fields ─────────────────────
        for int_field in ['years_at_address', 'nominee_age']:
            if data.get(int_field) == '':
                data[int_field] = None

        for date_field in ['gold_valuation_date']:
            if data.get(date_field) == '':
                data[date_field] = None

        serializer = GoldLoanApplicationCreateSerializer(data=data)
        if serializer.is_valid():
            gold_loan = serializer.save(user=user)

            Notification.objects.create(
                user    = user,
                title   = 'Gold Loan Application Submitted',
                summary = (
                    f'Your gold loan application for ₹{gold_loan.loan_amount} '
                    f'(Ref: {gold_loan.reference_number}) has been submitted successfully. '
                    f'Our team will contact you within 24 hours for a branch visit.'
                ),
            )

            return Response({
                'success': True,
                'message': 'Gold loan application submitted successfully.',
                'data':    self.serializer_class(gold_loan).data,
            }, status=status.HTTP_201_CREATED)

        return Response({
            'success': False,
            'errors':  serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)


# ──────────────────────────────────────────────────────────────────────────────
# GOLD LOAN APPLICATION — RETRIEVE + STATUS UPDATE + DELETE
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApplicationDetailEndpoint(BaseAPIView):
    """
    GET    → Retrieve a single gold loan application with all pledged ornaments.
    PATCH  → Admin only: update status, remarks, sanctioned amount, interest rate.
    DELETE → Admin only: remove pending or rejected applications only.
    """
    model              = GoldLoanApplication
    serializer_class   = GoldLoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def _get_gold_loan_or_none(self, request, pk):
        """Returns the GoldLoanApplication or None if not found / no access."""
        try:
            gold_loan = (
                GoldLoanApplication.objects
                .prefetch_related('pledged_ornaments')
                .get(pk=pk)
            )
        except GoldLoanApplication.DoesNotExist:
            return None

        if request.user.role != 'admin' and gold_loan.user != request.user:
            return None
        return gold_loan

    def get(self, request, pk):
        gold_loan = self._get_gold_loan_or_none(request, pk)
        if not gold_loan:
            return Response(
                {'success': False, 'message': 'Gold loan application not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({'success': True, 'data': self.serializer_class(gold_loan).data})

    def patch(self, request, pk):
        """
        Admin-only partial update.
        Allowed fields: status, admin_remarks, sanctioned_amount,
                        interest_rate, kyc_verified.
        Sends a notification to the applicant when status changes.
        """
        gold_loan = self._get_gold_loan_or_none(request, pk)
        if not gold_loan:
            return Response(
                {'success': False, 'message': 'Gold loan application not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if request.user.role != 'admin':
            return Response(
                {'success': False, 'message': 'Only admins can update a gold loan application.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        allowed_fields = {'status', 'admin_remarks', 'sanctioned_amount', 'interest_rate', 'kyc_verified'}
        update_data    = {k: v for k, v in request.data.items() if k in allowed_fields}

        for field, value in update_data.items():
            setattr(gold_loan, field, value)
        gold_loan.save(update_fields=list(update_data.keys()) + ['updated_at'])

        if 'status' in update_data:
            Notification.objects.create(
                user    = gold_loan.user,
                title   = 'Gold Loan Application Status Updated',
                summary = (
                    f'Your gold loan application (Ref: {gold_loan.reference_number}) '
                    f'status has been updated to: {gold_loan.get_status_display()}.'
                ),
            )

        return Response({
            'success': True,
            'message': 'Gold loan application updated successfully.',
            'data':    self.serializer_class(gold_loan).data,
        })

    def delete(self, request, pk):
        """
        Admin-only delete.
        Only pending or rejected gold loan applications can be removed.
        """
        gold_loan = self._get_gold_loan_or_none(request, pk)
        if not gold_loan:
            return Response(
                {'success': False, 'message': 'Gold loan application not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if request.user.role != 'admin':
            return Response(
                {'success': False, 'message': 'Only admins can delete a gold loan application.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        if gold_loan.status not in (LoanStatusChoices.PENDING, LoanStatusChoices.REJECTED):
            return Response({
                'success': False,
                'message': (
                    f'Cannot delete a gold loan application with status '
                    f'"{gold_loan.get_status_display()}". '
                    f'Only pending or rejected applications may be deleted.'
                ),
            }, status=status.HTTP_400_BAD_REQUEST)

        ref = gold_loan.reference_number
        gold_loan.delete()
        return Response({
            'success': True,
            'message': f'Gold loan application {ref} has been permanently deleted.',
        }, status=status.HTTP_200_OK)


# ──────────────────────────────────────────────────────────────────────────────
# GOLD LOAN APPLICATION — APPROVE / REJECT (ADMIN SHORTHAND)
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApprovalEndpoint(BaseAPIView):
    """
    POST → Admin shorthand action to approve or reject a gold loan application.
    Body: {
        "action":            "approve" | "reject",
        "remarks":           "...",
        "sanctioned_amount": 50000,     ← required when action = "approve"
        "interest_rate":     12.5        ← optional when approving
    }
    """
    model              = GoldLoanApplication
    serializer_class   = GoldLoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if request.user.role != 'admin':
            return Response(
                {'success': False, 'message': 'Only admins can approve or reject gold loan applications.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            gold_loan = GoldLoanApplication.objects.get(pk=pk)
        except GoldLoanApplication.DoesNotExist:
            return Response(
                {'success': False, 'message': 'Gold loan application not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        action = request.data.get('action')
        if action not in ('approve', 'reject'):
            return Response(
                {'success': False, 'message': 'action must be "approve" or "reject".'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if action == 'approve':
            sanctioned_amount = request.data.get('sanctioned_amount')
            if not sanctioned_amount:
                return Response(
                    {'success': False, 'message': 'sanctioned_amount is required when approving a gold loan.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            gold_loan.status            = LoanStatusChoices.APPROVED
            gold_loan.sanctioned_amount = sanctioned_amount
            gold_loan.interest_rate     = request.data.get('interest_rate')
            gold_loan.admin_remarks     = request.data.get('remarks', '')
            notification_title   = 'Gold Loan Application Approved 🎉'
            notification_summary = (
                f'Congratulations! Your gold loan application '
                f'(Ref: {gold_loan.reference_number}) has been approved '
                f'for ₹{sanctioned_amount} at {gold_loan.interest_rate}% p.a. '
                f'Please visit the branch within 7 days to complete disbursement.'
            )
        else:
            gold_loan.status        = LoanStatusChoices.REJECTED
            gold_loan.admin_remarks = request.data.get('remarks', '')
            notification_title   = 'Gold Loan Application Rejected'
            notification_summary = (
                f'Your gold loan application (Ref: {gold_loan.reference_number}) '
                f'could not be approved. '
                f'Reason: {gold_loan.admin_remarks or "Please contact the branch for more details."}'
            )

        gold_loan.save(update_fields=[
            'status', 'admin_remarks', 'sanctioned_amount', 'interest_rate', 'updated_at'
        ])

        Notification.objects.create(
            user    = gold_loan.user,
            title   = notification_title,
            summary = notification_summary,
        )

        return Response({
            'success': True,
            'message': f'Gold loan application {gold_loan.reference_number} has been {action}d.',
            'data':    self.serializer_class(gold_loan).data,
        })


# ──────────────────────────────────────────────────────────────────────────────
# PLEDGED ORNAMENTS — PER APPLICATION
# ──────────────────────────────────────────────────────────────────────────────

class PledgedOrnamentsListEndpoint(BaseAPIView):
    """
    GET → List all pledged gold ornaments for a specific gold loan application,
          along with weight and value totals.
    """
    model              = GoldLoanApplication
    serializer_class   = GoldLoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from .models import PledgedOrnament
        from .serializers import PledgedOrnamentSerializer

        try:
            gold_loan = GoldLoanApplication.objects.get(pk=pk)
        except GoldLoanApplication.DoesNotExist:
            return Response(
                {'success': False, 'message': 'Gold loan application not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if request.user.role != 'admin' and gold_loan.user != request.user:
            return Response(
                {'success': False, 'message': 'Permission denied.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        ornaments = gold_loan.pledged_ornaments.all()
        return Response({
            'success':              True,
            'reference_number':     gold_loan.reference_number,
            'total_ornament_items': ornaments.count(),
            'total_net_weight_g':   str(gold_loan.total_net_weight),
            'total_estimated_value': str(gold_loan.total_estimated_value),
            'data':                 PledgedOrnamentSerializer(ornaments, many=True).data,
        })


# ──────────────────────────────────────────────────────────────────────────────
# GOLD LOAN DASHBOARD STATISTICS
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanDashboardStatsEndpoint(BaseAPIView):
    """
    GET → Dashboard summary statistics for gold loan applications.
          Admin: platform-wide figures.
          Applicant: their own application stats only.
    """
    model              = GoldLoanApplication
    serializer_class   = GoldLoanApplicationSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        qs = (
            self.get_queryset()
            if user.role == 'admin'
            else self.get_queryset().filter(user=user)
        )

        # ── Application counts per status ─────────────────────────────────────
        status_counts = dict(
            qs.values_list('status')
              .annotate(count=Count('id'))
              .values_list('status', 'count')
        )
        application_status_breakdown = {s.value: 0 for s in LoanStatusChoices}
        application_status_breakdown.update(status_counts)

        # ── Financial & gold weight aggregates ────────────────────────────────
        aggregates = qs.aggregate(
            total_applications       = Count('id'),
            total_applied_amount     = Sum('loan_amount'),
            total_sanctioned_amount  = Sum('sanctioned_amount'),
            total_pledged_gold_grams = Sum('total_net_weight'),
            total_pledged_gold_value = Sum('total_estimated_value'),
        )

        # ── 5 most recent gold loan submissions ───────────────────────────────
        recent_gold_loan_applications = qs.order_by('-created_at')[:5]

        return Response({
            'success': True,
            'data': {
                'applicationStatusBreakdown':   application_status_breakdown,
                'totalGoldLoanApplications':    aggregates['total_applications'] or 0,
                'totalAppliedLoanAmount':       str(aggregates['total_applied_amount'] or 0),
                'totalSanctionedLoanAmount':    str(aggregates['total_sanctioned_amount'] or 0),
                'totalPledgedGoldWeightGrams':  str(aggregates['total_pledged_gold_grams'] or 0),
                'totalPledgedGoldEstimatedValue': str(aggregates['total_pledged_gold_value'] or 0),
                'recentGoldLoanApplications':   self.serializer_class(recent_gold_loan_applications, many=True).data,
            },
        })
class GoldRateEndpoint(BaseAPIView):
    def get(request):
        try:
            res = requests.get(
                "https://www.goodreturns.in/gold-rates-in-hyderabad.html",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=5
            )
            soup = BeautifulSoup(res.text, "html.parser")
            rate = soup.select_one("#gold_price_table tr:nth-child(2) td:nth-child(2)")
            return JsonResponse({"success": True, "rate": rate.text.strip().replace(",", "")})
        except Exception as e:
            return JsonResponse({"success": False, "rate": None})
