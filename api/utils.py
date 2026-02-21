from django.conf import settings
from twilio.rest import Client
from supabase import create_client
import jwt
from datetime import datetime, timedelta
from PIL import Image
from io import BytesIO
import base64


# ========================================
# JWT HELPER FUNCTIONS
# ========================================

def generate_jwt_tokens(user):
    """Generate access and refresh tokens for user"""
    
    access_token_payload = {
        'id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_ACCESS_TOKEN_LIFETIME)
    }
    
    refresh_token_payload = {
        'id': user.id,
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_REFRESH_TOKEN_LIFETIME)
    }
    
    access_token = jwt.encode(
        access_token_payload,
        settings.JWT_SECRET,
        algorithm='HS256'
    )
    
    refresh_token = jwt.encode(
        refresh_token_payload,
        settings.JWT_SECRET,
        algorithm='HS256'
    )
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }


# ========================================
# TWILIO SMS FUNCTIONS
# ========================================

def send_otp_via_twilio(mobile_number, otp):
    """Send OTP via Twilio SMS"""
    
    try:
        client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        
        message = client.messages.create(
            body=f'RK Fin-Care OTP: {otp}. Do not share this OTP.',
            from_=settings.TWILIO_PHONE_NUMBER,
            to=f'+91{mobile_number}'
        )
        
        print(f'✅ OTP sent to {mobile_number}: {otp}')
        return True
        
    except Exception as e:
        print(f'❌ Twilio Error: {str(e)}')
        return False


def send_whatsapp_message(phone_number, message):
    """Send WhatsApp message via Twilio"""
    
    try:
        client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        )
        
        message = client.messages.create(
            from_='whatsapp:+14155238886',
            to=f'whatsapp:{phone_number}',
            body=message
        )
        
        print(f'✅ WhatsApp message sent to {phone_number}')
        return True
        
    except Exception as e:
        print(f'❌ WhatsApp Error: {str(e)}')
        return False


# ========================================
# SUPABASE STORAGE FUNCTIONS
# ========================================

def get_supabase_client():
    """Get Supabase client instance"""
    return create_client(
        settings.SUPABASE_URL,
        settings.SUPABASE_KEY
    )


def upload_to_supabase(file_buffer, file_name, mime_type):
    """Upload file to Supabase storage"""
    
    try:
        supabase = get_supabase_client()
        
        # Upload file
        response = supabase.storage.from_(settings.SUPABASE_BUCKET_NAME).upload(
            file_name,
            file_buffer,
            {
                'content-type': mime_type,
                'upsert': 'true'
            }
        )
        
        # Get public URL
        public_url = supabase.storage.from_(settings.SUPABASE_BUCKET_NAME).get_public_url(file_name)
        
        print(f'✅ File uploaded to Supabase: {file_name}')
        return public_url
        
    except Exception as e:
        print(f'❌ Supabase upload error: {str(e)}')
        return None


def download_from_supabase(file_path):
    """Download file from Supabase storage"""
    
    try:
        supabase = get_supabase_client()
        
        response = supabase.storage.from_(settings.SUPABASE_BUCKET_NAME).download(file_path)
        
        return response
        
    except Exception as e:
        print(f'❌ Supabase download error: {str(e)}')
        return None


# ========================================
# PDF/IMAGE PROCESSING FUNCTIONS
# ========================================

def normalize_image_to_png(image_buffer):
    """Convert image to PNG format"""
    
    try:
        from PIL import Image
        
        img = Image.open(BytesIO(image_buffer))
        
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        
        # Save as PNG
        output = BytesIO()
        img.save(output, format='PNG')
        return output.getvalue()
        
    except Exception as e:
        print(f'❌ Image normalization error: {str(e)}')
        raise


def base64_to_buffer(base64_string):
    """Convert base64 string to bytes"""
    
    # Remove data URL prefix if present
    if ',' in base64_string:
        base64_string = base64_string.split(',')[1]
    
    return base64.b64decode(base64_string)


def detect_base64_type(base64_string):
    """Detect MIME type from base64 string"""
    
    if base64_string.startswith('data:'):
        mime_type = base64_string.split(';')[0].replace('data:', '')
        return mime_type
    
    return None


def convert_image_to_pdf(image_buffer):
    """Convert image to PDF"""
    
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from PIL import Image
        
        # Normalize to PNG first
        png_buffer = normalize_image_to_png(image_buffer)
        
        # Open image to get dimensions
        img = Image.open(BytesIO(png_buffer))
        img_width, img_height = img.size
        
        # Create PDF
        pdf_buffer = BytesIO()
        c = canvas.Canvas(pdf_buffer, pagesize=(img_width, img_height))
        
        # Draw image
        c.drawImage(
            BytesIO(png_buffer),
            0, 0,
            width=img_width,
            height=img_height
        )
        
        c.save()
        
        return pdf_buffer.getvalue()
        
    except Exception as e:
        print(f'❌ Image to PDF conversion error: {str(e)}')
        raise


def generate_signed_pdf(pdf_buffer, signature_buffer, signature_mime):
    """Add signature to PDF"""
    
    try:
        from PyPDF2 import PdfReader, PdfWriter
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from PIL import Image
        
        # Normalize signature to PNG
        if signature_mime.startswith('image/'):
            png_signature = normalize_image_to_png(signature_buffer)
        else:
            raise ValueError('Signature must be an image')
        
        # Read existing PDF
        pdf_reader = PdfReader(BytesIO(pdf_buffer))
        pdf_writer = PdfWriter()
        
        # Get first page
        first_page = pdf_reader.pages[0]
        page_width = float(first_page.mediabox.width)
        page_height = float(first_page.mediabox.height)
        
        # Create signature overlay
        signature_img = Image.open(BytesIO(png_signature))
        sig_width = 150
        sig_height = 50
        
        packet = BytesIO()
        c = canvas.Canvas(packet, pagesize=(page_width, page_height))
        
        # Position signature at bottom right
        c.drawImage(
            BytesIO(png_signature),
            page_width - sig_width - 50,
            50,
            width=sig_width,
            height=sig_height,
            preserveAspectRatio=True
        )
        
        c.save()
        
        # Merge with original page
        packet.seek(0)
        overlay_pdf = PdfReader(packet)
        first_page.merge_page(overlay_pdf.pages[0])
        
        # Add all pages
        for page in pdf_reader.pages:
            pdf_writer.add_page(page)
        
        # Write to output
        output = BytesIO()
        pdf_writer.write(output)
        
        return output.getvalue()
        
    except Exception as e:
        print(f'❌ PDF signing error: {str(e)}')
        raise


def is_pdf_buffer(buffer):
    """Check if buffer is a PDF"""
    return buffer[:4] == b'%PDF'