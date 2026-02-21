import re
import datetime
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import jwt
from .models import User


class JWTAuthentication(BaseAuthentication):
    """Custom JWT authentication"""

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return None

        try:
            # Extract token from "Bearer <token>"
            parts = auth_header.split()
            if parts[0].lower() != 'bearer' or len(parts) != 2:
                raise AuthenticationFailed('Invalid authorization header format')

            token = parts[1]

            # Decode token
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=['HS256']
            )

            # Get user
            user_id = payload.get('id')
            if not user_id:
                raise AuthenticationFailed('Invalid token payload')

            user = User.objects.filter(id=user_id, is_active=True).first()
            if not user:
                raise AuthenticationFailed('User not found or inactive')

            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f'Authentication failed: {str(e)}')


# ========================================
# REGEX PATTERNS
# ========================================

PHONE_NUMBER_REGEX_PATTERN = ".*?(\\(?\\d{3}\\D{0,3}\\d{3}\\D{0,3}\\d{4}).*?"
EMAIL_ADDRESS_REGEX_PATTERN = (
    "([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\\.[A-Z|a-z]{2,})+"
)


def check_valid_phone_number(phone_number):
    if len(phone_number) > 15:
        return False
    pattern = re.compile(PHONE_NUMBER_REGEX_PATTERN)
    return pattern.match(phone_number)


def check_valid_email_address(email_address):
    pattern = re.compile(EMAIL_ADDRESS_REGEX_PATTERN)
    return pattern.match(email_address)


# ========================================
# TOKEN GENERATION - matches Node.js JWT format exactly
# ========================================

def get_tokens_for_user(user):
    """Generate JWT tokens matching Node.js format exactly"""

    access_payload = {
        'id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
    }

    refresh_payload = {
        'id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }

    access_token = jwt.encode(access_payload, settings.JWT_SECRET, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, settings.JWT_SECRET, algorithm='HS256')

    return (access_token, refresh_token)


def generate_jwt_tokens(user):
    """Alias for get_tokens_for_user — returns dict format"""

    access_payload = {
        'id': user.id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
    }

    refresh_payload = {
        'id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }

    access_token = jwt.encode(access_payload, settings.JWT_SECRET, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, settings.JWT_SECRET, algorithm='HS256')

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
    }


# ========================================
# PASSWORD VALIDATION
# ========================================

def validate_password(password):
    """
    Validate password strength:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    if not password:
        return False, "Password is required"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least 1 uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least 1 lowercase letter"

    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least 1 digit"

    special_char_pattern = r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]'
    if not re.search(special_char_pattern, password):
        return False, "Password must contain at least 1 special character (!@#$%^&* etc.)"

    return True, None