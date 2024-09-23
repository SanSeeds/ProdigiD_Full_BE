from io import BytesIO
import io
import os
import random
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse, JsonResponse
from gtts import gTTS
from .email_llama3 import add_slide, ask_question_chatbot, generate_blog, generate_slide_titles, extract_document_content, generate_email, bhashini_translate,generate_bus_pro, generate_offer_letter, generate_slide_content, generate_slide_titles, generate_summary, generate_content, generate_sales_script, rephrasely  
from django.contrib.auth.models import User
from django.utils.crypto import get_random_string
from django.utils import timezone
from rest_framework_api_key.permissions import HasAPIKey
from django.conf import settings
from datetime import date, timedelta
from .models import EmailVerificationOTP, PasswordResetRequest, Payment, Profile, TemporaryEmailVerificationOTP, UserService, UserSession
from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth import update_session_auth_hash
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
import json
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.password_validation import validate_password  
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from django.contrib.auth.hashers import make_password  # Import the function
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.renderers import BaseRenderer
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from django.core.files.storage import default_storage
from django.utils.dateparse import parse_date
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.core.files.storage import default_storage
from django.shortcuts import render
import fitz  # PyMuPDF
from docx import Document as DocxDocument
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from datetime import timedelta
from django.utils import timezone
from dateutil.relativedelta import relativedelta
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
# from validate_email_address import validate_email
import dns.resolver
from django.views.decorators.csrf import csrf_exempt
import json
import logging
import dns.resolver
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.utils import timezone
import json
import razorpay

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import json
from django.views.decorators.csrf import ensure_csrf_cookie

logger = logging.getLogger(__name__)


def test_report(request):
    report_path = os.path.join(os.path.dirname(__file__), 'report.html')
    with open(report_path, 'r') as file:
        report_content = file.read()
    return render(request, 'test_report.html', {'report_content': report_content})


# Base64-encoded AES IV and Secret Key
AES_IV_b64 = settings.AES_IV
AES_SECRET_KEY_b64 = settings.AES_SECRET_KEY
ENCRYPTION_IV_b64 = settings.ENCRYPTION_IV
ENCRYPTION_SECRET_KEY_b64 = settings.ENCRYPTION_SECRET_KEY

# Decode Base64 strings to bytes
AES_IV = base64.b64decode(AES_IV_b64)
AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY_b64)
ENCRYPTION_IV = base64.b64decode(ENCRYPTION_IV_b64)
ENCRYPTION_SECRET_KEY = base64.b64decode(ENCRYPTION_SECRET_KEY_b64)

# Decode Base64 strings to bytes
AES_IV = base64.b64decode(AES_IV_b64)
AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY_b64)


# Ensure IV is 16 bytes long (128 bits)
if len(AES_IV) != 16:
    raise ValueError("AES IV must be 16 bytes long")

razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


class CustomAesRenderer(BaseRenderer):
    media_type = 'application/octet-stream'
    format = 'aes'

    def render(self, data, media_type=None, renderer_context=None):
        plaintext = json.dumps(data)
        padded_plaintext = pad(plaintext.encode(), 16)
        cipher = AES.new(AES_SECRET_KEY, AES.MODE_CBC, AES_IV)
        ciphertext = cipher.encrypt(padded_plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext).decode()
        response = {'ciphertext': ciphertext_b64}
        return json.dumps(response)

def landing(request):
    return render(request, 'landing.html')

def about(request):
    return render(request, 'about.html')


# @api_view(['GET'])
# @permission_classes([])
# def get_keys(request):
#     # Return sensitive information as a JSON response
#     data = {
#         'api_key': settings.API_KEY,
#         'aes_iv': settings.AES_IV,
#         'aes_secret_key': settings.AES_SECRET_KEY,
#     }
#     return JsonResponse(data)



@csrf_exempt
def create_razorpay_order(request):
    if request.method == "POST":
        try:
            # Fetch data (amount and email) from the request
            data = json.loads(request.body)
            amount = data.get('amount', 0) * 100  # Convert to paise
            email = data.get('email')  # Extract email from the request
            
            if not email:
                return JsonResponse({"error": "Email is required"}, status=400)

            # Create Razorpay order
            razorpay_order = razorpay_client.order.create({
                "amount": amount,
                "currency": "INR",
                "payment_capture": "1"
            })

            # Save order details to the Payment table including the email
            Payment.objects.create(
                order_id=razorpay_order['id'],
                amount=amount / 100,  # Convert back to rupees
                currency="INR",
                payment_capture=True,
                email=email  # Store the email
            )

            # Return the order ID and other details
            return JsonResponse({
                "order_id": razorpay_order['id'],
                "amount": amount,
                "currency": "INR",
                "razorpay_key_id": settings.RAZORPAY_KEY_ID
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def verify_payment(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            razorpay_order_id = data.get('razorpay_order_id')
            razorpay_payment_id = data.get('razorpay_payment_id')
            razorpay_signature = data.get('razorpay_signature')
            selected_services = data.get('selected_services')  # Directly use the services payload
            email = data.get('email')  # Extract email from the request

            logger.info(f"Received payment verification request with order_id: {razorpay_order_id}, payment_id: {razorpay_payment_id}, signature: {razorpay_signature}")

            # Verify payment signature
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }

            try:
                # Verify the payment signature
                razorpay_client.utility.verify_payment_signature(params_dict)
                logger.info("Payment signature verification successful")

                # Update the Payment record
                payment = Payment.objects.get(order_id=razorpay_order_id)
                payment.payment_id = razorpay_payment_id
                payment.signature = razorpay_signature
                payment.email = email
                payment.verified = True  # Mark the payment as verified
                payment.save()

                # Process the selected services
                if not selected_services or not email:
                    return JsonResponse({'error': 'No services or email found in the request.'}, status=400)

                # Get or create the user and user services
                user = get_object_or_404(User, email=email)
                user_services, created = UserService.objects.get_or_create(user=user)

                # List of subscribed services for the email
                subscribed_services = []

                # Check if "Introductory Offer" is selected
                if selected_services.get("introductory_offer_service", False):
                    # Set all services to 1
                    user_services.email_service = 1
                    user_services.offer_letter_service = 1
                    user_services.business_proposal_service = 1
                    user_services.sales_script_service = 1
                    user_services.content_generation_service = 1
                    user_services.summarize_service = 1
                    user_services.ppt_generation_service = 1
                    user_services.blog_generation_service = 1
                    user_services.rephrasely_service = 1

                    # Add all services to the subscribed list
                    subscribed_services = [
                        "Email Service", "Offer Letter Service", "Business Proposal Service",
                        "Sales Script Service", "Content Generation Service", "Summarize Service",
                        "PPT Generation Service", "Blog Generation Service", "Rephrasely Service"
                    ]
                else:
                    # Update services based on the data and add to subscribed list if activated
                    if selected_services.get("email_service", 0) > 0:
                        user_services.email_service = 1
                        subscribed_services.append("Email Service")
                    if selected_services.get("offer_letter_service", 0) > 0:
                        user_services.offer_letter_service = 1
                        subscribed_services.append("Offer Letter Service")
                    if selected_services.get("business_proposal_service", 0) > 0:
                        user_services.business_proposal_service = 1
                        subscribed_services.append("Business Proposal Service")
                    if selected_services.get("sales_script_service", 0) > 0:
                        user_services.sales_script_service = 1
                        subscribed_services.append("Sales Script Service")
                    if selected_services.get("content_generation_service", 0) > 0:
                        user_services.content_generation_service = 1
                        subscribed_services.append("Content Generation Service")
                    if selected_services.get("summarize_service", 0) > 0:
                        user_services.summarize_service = 1
                        subscribed_services.append("Summarize Service")
                    if selected_services.get("ppt_generation_service", 0) > 0:
                        user_services.ppt_generation_service = 1
                        subscribed_services.append("PPT Generation Service")
                    if selected_services.get("blog_generation_service", 0) > 0:
                        user_services.blog_generation_service = 1
                        subscribed_services.append("Blog Generation Service")
                    if selected_services.get("rephrasely_service", 0) > 0:
                        user_services.rephrasely_service = 1
                        subscribed_services.append("Rephrasely Service")

                # Save the updated user services
                user_services.save()

                # Create email content with only subscribed services
                subscribed_services_str = "\n".join(f"- {service}" for service in subscribed_services)
                subject = 'Greetings from ProdigiDesk'
                message = f"""
                    Dear Sir/Madam,

                    We’re thrilled to have you onboard! By subscribing to our services, you've unlocked access to a world of exclusive features tailored to help you achieve your goals.
                    You have subscribed to the following services, all valid for one month:
                    {subscribed_services_str}

                    If you have any questions, don’t hesitate to reach out to us. Let’s make the most of your subscription!

                    Best regards,
                    ProdigiDesk Team
                    """
                from_email = settings.DEFAULT_FROM_EMAIL
                recipient_list = [email]

                try:
                    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                    logger.info(f"Registration success email sent to {email}")
                except Exception as e:
                    logger.error(f"Error sending registration success email: {str(e)}")

                # Return success response
                return JsonResponse({'message': 'Payment and service save successful'}, status=200)

            except razorpay.errors.SignatureVerificationError:
                logger.error("Payment signature verification failed")
                return JsonResponse({"status": "Payment verification failed"}, status=400)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format")
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            logger.error(f"Exception occurred: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)


def encrypt_data(data):
    plaintext = json.dumps(data)
    padded_plaintext = pad(plaintext.encode(), 16)
    cipher = AES.new(ENCRYPTION_SECRET_KEY, AES.MODE_CBC, ENCRYPTION_IV)
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return ciphertext_b64


def decrypt_data(encrypted_data):
    try:
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(ENCRYPTION_SECRET_KEY, AES.MODE_CBC, ENCRYPTION_IV)
        decrypted_data = unpad(cipher.decrypt(encrypted_data_bytes), 16)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption error: {e}")

#Encrypted API to sign up a new user
@csrf_exempt
def add_user(request):
    if request.method == 'POST':
        try:
            # Load and decode the request body
            body = request.body.decode('utf-8')
            logger.debug(f"Request body received: {body}")

            # Extract and decrypt the incoming payload
            data = json.loads(body)
            encrypted_content = data.get('encrypted_content')
            if not encrypted_content:
                logger.warning("No encrypted content found in the request.")
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            logger.debug(f"Encrypted content received: {encrypted_content}")
            decrypted_content = decrypt_data(encrypted_content)  # Decrypt the content using your custom decrypt_data function
            logger.debug(f"Decrypted content: {decrypted_content}")

            content = json.loads(decrypted_content)

            if not content:
                logger.warning('No content found in the request.')
                return JsonResponse({'error': 'No content found in the request.'}, status=400)

            # Extract required fields
            first_name = content.get('first_name')
            last_name = content.get('last_name')
            username = content.get('username')
            email = content.get('email')
            password = content.get('password')
            confirm_password = content.get('confirm_password')

            # Check if username and email are provided
            if not username:
                return JsonResponse({'error': 'Username is required.'}, status=400)
            if not email:
                return JsonResponse({'error': 'Email is required.'}, status=400)

            # Normalize username and email to lowercase
            username = username.lower()
            email = email.lower()

            # Check if passwords match
            if password != confirm_password:
                return JsonResponse({'error': 'Passwords do not match.'}, status=400)

            # Check if username already exists
            if User.objects.filter(username=username).exists():
                return JsonResponse({'error': 'Username already exists.'}, status=400)

            # Validate email
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'error': 'Invalid email address.'}, status=400)

            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already exists.'}, status=400)

            # Create user
            user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=make_password(password)  # Hash the password
            )
            user.save()

            # Prepare the response
            response_data = {
                'message': 'User created successfully',
                'user_id': user.id,
                'email': email
            }

            # Encrypt the response content
            encrypted_response_content = encrypt_data(response_data)  # Encrypt the response using your custom encrypt_data function

            # Return the encrypted response
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=201)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format in request")
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        logger.error("Invalid request method")
        return JsonResponse({'error': 'Invalid request method'}, status=405)


#Encrypted API to send otp over email while registering a new user
@csrf_exempt
def send_email_verification_otp(request):
    if request.method == 'POST':
        try:
            # Load and decode the request body
            body = request.body.decode('utf-8')
            logger.debug(f"Request body received: {body}")

            # Extract and decrypt the incoming payload
            data = json.loads(body)
            encrypted_content = data.get('encrypted_content')
            if not encrypted_content:
                logger.warning("No encrypted content found in the request.")
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            logger.debug(f"Encrypted content received: {encrypted_content}")
            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f"Decrypted content: {decrypted_content}")

            data = json.loads(decrypted_content)

            # Extract email from the decrypted payload
            email = data.get('email')
            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            # Check if the email is already registered
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email is already registered'}, status=400)

            # Generate OTP and set expiry time
            otp = generate_otp()
            expiry_time = timezone.now() + timedelta(minutes=10)

            # Save OTP and its expiry in the database
            TemporaryEmailVerificationOTP.objects.update_or_create(
                email=email,
                defaults={
                    'otp': otp,
                    'expiry_time': expiry_time
                }
            )

            # Send OTP via email
            subject = 'Welcome to ProdigiDesk'
            plain_message = f"""
Dear Sir/Madam,

System generated confidential OTP {otp} is valid for 10 mins.

This is a system generated mail. Please do not reply.

Regards,
ProdigiDesk Team
"""
            html_message = f"""
<p>Dear Sir/Madam,</p>
<p>System generated confidential OTP <strong>{otp}</strong> is valid for 10 mins.</p>
<p>This is a system generated mail. Please do not reply.</p>
<p>Regards,<br>ProdigiDesk Team</p>
"""

            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [email]

            try:
                send_mail(
                    subject, 
                    plain_message, 
                    from_email, 
                    recipient_list, 
                    fail_silently=False,
                    html_message=html_message  # Add HTML content here
                )
            except Exception as e:
                return JsonResponse({'error': f'Error sending email: {str(e)}'}, status=500)

            # Encrypt the response content
            encrypted_response_content = encrypt_data({'success': 'OTP sent successfully'})

            # Return the encrypted response
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format received.")
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)



#Encrypted API to verify otp while registering a new user
@csrf_exempt
def otp_verify(request):
    if request.method == 'POST':
        try:
            # Load and decode the request body
            body = request.body.decode('utf-8')
            logger.debug(f"Request body received: {body}")

            # Extract and decrypt the incoming payload
            data = json.loads(body)
            encrypted_content = data.get('encrypted_content')
            if not encrypted_content:
                logger.warning("No encrypted content found in the request.")
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            logger.debug(f"Encrypted content received: {encrypted_content}")
            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f"Decrypted content: {decrypted_content}")

            data = json.loads(decrypted_content)
            otp = data.get('otp')

            if not otp:
                return JsonResponse({'error': 'OTP is required.'}, status=400)

            try:
                # Fetch the OTP record based on the OTP provided
                otp_record = TemporaryEmailVerificationOTP.objects.get(otp=otp)
            except TemporaryEmailVerificationOTP.DoesNotExist:
                # If OTP does not exist, return error and delete any related records
                TemporaryEmailVerificationOTP.objects.filter(otp=otp).delete()
                encrypted_response_content = encrypt_data({'error': 'Invalid OTP'})
                return JsonResponse({'encrypted_content': encrypted_response_content}, status=400)

            # Check if the OTP has expired
            if otp_record.expiry_time < timezone.now():
                # Delete OTP record if expired
                otp_record.delete()
                encrypted_response_content = encrypt_data({'error': 'OTP has expired'})
                return JsonResponse({'encrypted_content': encrypted_response_content}, status=400)

            # If OTP is valid and not expired, proceed with verification
            otp_record.delete()

            # Encrypt the success response
            encrypted_response_content = encrypt_data({'success': 'OTP verified successfully'})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format received.")
            encrypted_response_content = encrypt_data({'error': 'Invalid JSON format.'})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=400)
        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            encrypted_response_content = encrypt_data({'error': str(e)})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


#Encrypted API To Send Feedback
@csrf_exempt
def send_feedback(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f'Encrypted content received: {encrypted_content}')

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f'Decrypted content: {decrypted_content}')
            data = json.loads(decrypted_content)

            # Extract feedback and userEmail from decrypted content
            feedback_text = data.get('feedback')
            user_email = data.get('userEmail')

            if not feedback_text or not user_email:
                logger.warning('Feedback text or userEmail is missing.')
                return JsonResponse({'error': 'Missing feedback text or userEmail'}, status=400)

            # Compose the email
            subject = 'New Feedback Submission'
            message = f'User Email: {user_email}\n\nFeedback:\n{feedback_text}\n\n'

            # Send the email
            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,  # From email, defined in settings.py
                ['info@prodigidesk.ai'],  # Replace with the recipient's email
                fail_silently=False
            )

            logger.info(f"Feedback email sent successfully from {user_email}")

            # Encrypt the response message
            encrypted_response = encrypt_data({'message': 'Feedback sent successfully'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        logger.error('Invalid request method')
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def save_selected_services(request):
    if request.method == "POST":
        try:
            # Decode the request body
            body = request.body.decode('utf-8')

            # Extract and decrypt the incoming payload
            data = json.loads(body)
            encrypted_content = data.get('encrypted_content')
            if not encrypted_content:
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            # Decrypt the content
            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)

            # Extract email and selected services
            email = data.get("email")
            selected_services = data.get("selected_services", {})

            # Get or create the user and user services
            user = get_object_or_404(User, email=email)
            user_services, created = UserService.objects.get_or_create(user=user)

            # Check if "Introductory Offer" is selected
            if selected_services.get("introductory_offer_service", False):
                # Set all services to 1
                user_services.email_service = 1
                user_services.offer_letter_service = 1
                user_services.business_proposal_service = 1
                user_services.sales_script_service = 1
                user_services.content_generation_service = 1
                user_services.summarize_service = 1
                user_services.ppt_generation_service = 1
                user_services.blog_generation_service = 1
                user_services.rephrasely_service = 1
            else:
                # Update services based on the data
                user_services.email_service = selected_services.get("email_service", user_services.email_service)
                user_services.offer_letter_service = selected_services.get("offer_letter_service", user_services.offer_letter_service)
                user_services.business_proposal_service = selected_services.get("business_proposal_service", user_services.business_proposal_service)
                user_services.sales_script_service = selected_services.get("sales_script_service", user_services.sales_script_service)
                user_services.content_generation_service = selected_services.get("content_generation_service", user_services.content_generation_service)
                user_services.summarize_service = selected_services.get("summarize_service", user_services.summarize_service)
                user_services.ppt_generation_service = selected_services.get("ppt_generation_service", user_services.ppt_generation_service)
                user_services.blog_generation_service = selected_services.get("blog_generation_service", user_services.blog_generation_service)
                user_services.rephrasely_service = selected_services.get("rephrasely_service", user_services.rephrasely_service)

            # Save the updated user services
            user_services.save()

            # Encrypt the success response
            encrypted_response_content = encrypt_data({'message': 'Services saved successfully'})

            # Return the encrypted response
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt  
def update_user_services(request, email):
    if request.method == "POST":
        # Retrieve the user and their services
        user = get_object_or_404(User, email=email)
        user_services = get_object_or_404(UserService, user=user)
        
        # Parse the JSON data from the request body
        try:
            services_data = json.loads(request.body).get("selected_services", {})
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        # Update the services dynamically based on the mapping from the frontend
        service_mapping = {
            "email_service": "email_service",
            "offer_letter_service": "offer_letter_service",
            "business_proposal_service": "business_proposal_service",
            "sales_script_service": "sales_script_service",
            "content_generation_service": "content_generation_service",
            "summarize_service": "summarize_service",
            "ppt_generation_service": "ppt_generation_service",
            "blog_generation_service": "blog_generation_service",  # New Service
            "rephrasely_service": "rephrasely_service",            # New Service
        }

        # Update user services based on received data
        for service_key, db_field in service_mapping.items():
            if service_key in services_data:
                setattr(user_services, db_field, services_data[service_key])

        # Save the updated user services
        user_services.save()

        return JsonResponse({"success": True, "message": "Services updated successfully."})

    return JsonResponse({"error": "Invalid request method"}, status=400)


#Encrypted API To get all user Services
def get_user_services(request, email):
    if request.method == "GET":
        try:
            user = get_object_or_404(User, email=email)
            user_services = get_object_or_404(UserService, user=user)

            services = {
                "email_service": {
                    "id": 1,
                    "is_active": user_services.email_service and (user_services.email_end_date >= date.today()),
                    "end_date": user_services.email_end_date.isoformat() if user_services.email_end_date else None,
                },
                "offer_letter_service": {
                    "id": 2,
                    "is_active": user_services.offer_letter_service and (user_services.offer_letter_end_date >= date.today()),
                    "end_date": user_services.offer_letter_end_date.isoformat() if user_services.offer_letter_end_date else None,
                },
                "business_proposal_service": {
                    "id": 3,
                    "is_active": user_services.business_proposal_service and (user_services.business_proposal_end_date >= date.today()),
                    "end_date": user_services.business_proposal_end_date.isoformat() if user_services.business_proposal_end_date else None,
                },
                "sales_script_service": {
                    "id": 4,
                    "is_active": user_services.sales_script_service and (user_services.sales_script_end_date >= date.today()),
                    "end_date": user_services.sales_script_end_date.isoformat() if user_services.sales_script_end_date else None,
                },
                "content_generation_service": {
                    "id": 5,
                    "is_active": user_services.content_generation_service and (user_services.content_generation_end_date >= date.today()),
                    "end_date": user_services.content_generation_end_date.isoformat() if user_services.content_generation_end_date else None,
                },
                "summarize_service": {
                    "id": 6,
                    "is_active": user_services.summarize_service and (user_services.summarize_end_date >= date.today()),
                    "end_date": user_services.summarize_end_date.isoformat() if user_services.summarize_end_date else None,
                },
                "ppt_generation_service": {
                    "id": 7,
                    "is_active": user_services.ppt_generation_service and (user_services.ppt_generation_end_date >= date.today()),
                    "end_date": user_services.ppt_generation_end_date.isoformat() if user_services.ppt_generation_end_date else None,
                },
                "blog_generation_service": {
                    "id": 9,
                    "is_active": user_services.blog_generation_service and (user_services.blog_generation_end_date >= date.today()),
                    "end_date": user_services.blog_generation_end_date.isoformat() if user_services.blog_generation_end_date else None,
                },
                "rephrasely_service": {
                    "id": 10,
                    "is_active": user_services.rephrasely_service and (user_services.rephrasely_end_date >= date.today()),
                    "end_date": user_services.rephrasely_end_date.isoformat() if user_services.rephrasely_end_date else None,
                },
            }

            # Encrypt the response content
            encrypted_services = encrypt_data({"user_id": user.id, "services": services})

            return JsonResponse({'encrypted_content': encrypted_services}, status=200)

        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except UserService.DoesNotExist:
            return JsonResponse({"error": "User services not found"}, status=404)

    return JsonResponse({"error": "Invalid request method"}, status=400)


def generate_otp():
    return ''.join(random.choices('0123456789', k=6))

#Encrypted API to send OTP for Password Reset
@csrf_exempt
def send_otp(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f"Encrypted content received: {encrypted_content}")

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f"Decrypted content: {decrypted_content}")
            data = json.loads(decrypted_content)

            email = data.get('email')
            logger.debug(f"Received OTP request for email: {email}")

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                logger.warning(f"Email does not exist: {email}")
                encrypted_response = encrypt_data({'error': 'Email does not exist'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=404)

            # Generate OTP
            otp = generate_otp()
            expiry_time = timezone.now() + timedelta(minutes=10)

            # Store OTP and expiry time in the database
            PasswordResetRequest.objects.update_or_create(
                user=user,
                defaults={
                    'otp': otp,
                    'expiry_time': expiry_time
                }
            )
            logger.info(f"Generated OTP for user {user.username}")

            # Send OTP via email
            subject = 'Password Reset OTP'
            message = f'Your OTP for password reset is {otp}. This OTP is valid only for 10 minutes.'
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [email]

            try:
                send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                logger.info(f"OTP email sent to {email}")
            except Exception as e:
                logger.error(f"Error sending email: {str(e)}")
                encrypted_response = encrypt_data({'error': f'Error sending email: {str(e)}'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=500)

            encrypted_response = encrypt_data({'success': 'OTP sent successfully'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error("Invalid JSON format in request")
            encrypted_response = encrypt_data({'error': 'Invalid JSON format'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            encrypted_response = encrypt_data({'error': str(e)})
            return JsonResponse({'encrypted_content': encrypted_response}, status=500)

    logger.error("Invalid request method")
    encrypted_response = encrypt_data({'error': 'Invalid request method'})
    return JsonResponse({'encrypted_content': encrypted_response}, status=405)



#Encrypted API to Sign the user in
@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)
            
            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f'Decrypted content: {data}')

            login_input = data.get('login_input').lower()
            password = data.get('password')
            logout_from_all = data.get('logout_from_all', False)  # Check if the checkbox is set

            if not login_input or not password:
                logger.warning('Login input and password are required')
                return JsonResponse({'error': 'Login input and password are required'}, status=400)

            try:
                if '@' in login_input:
                    user = User.objects.get(email=login_input)
                else:
                    user = User.objects.get(username=login_input)
            except User.DoesNotExist:
                logger.warning('Username or email not found')
                return JsonResponse({'error': 'Username or email not found'}, status=401)

            # Check if the user has an active session
            if logout_from_all:
                # Mark all previous sessions as inactive
                UserSession.objects.filter(user=user, active=True).update(active=False)

            active_session = UserSession.objects.filter(user=user, active=True).first()
            if active_session and not logout_from_all:
                logger.warning('User already logged in with an active session')
                return JsonResponse({'error': 'User already logged in'}, status=403)

            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                logger.info(f'User {user.username} authenticated successfully')

                # Create a new session
                session_id = get_random_string(length=32)
                UserSession.objects.create(user=user, session_id=session_id, email=user.email, active=True)  # Include email here

                logger.debug(f'Session created with ID: {session_id}')

                encrypted_response = encrypt_data({
                    'success': 'User authenticated',
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user_id': user.id,
                    'session_id': session_id  # Include session_id in the response
                })

                return JsonResponse({'encrypted_content': encrypted_response}, status=200)
            else:
                logger.warning('Password not correct')
                return JsonResponse({'error': 'Password not correct'}, status=401)
        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f'Internal server error: {str(e)}')
            return JsonResponse({'error': 'Internal server error'}, status=500)
    else:
        logger.error('Invalid request method')
        return JsonResponse({'error': 'Invalid request method'}, status=405)


# @csrf_protect  # Enable CSRF protection
# def signin(request):
#     if request.method == 'POST':
#         try:
#             encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
#             if not encrypted_content:
#                 logger.warning('No encrypted content found in the request.')
#                 return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

#             decrypted_content = decrypt_data(encrypted_content)
#             data = json.loads(decrypted_content)
#             logger.debug(f'Decrypted content: {data}')

#             login_input = data.get('login_input').lower()
#             password = data.get('password')
#             logout_from_all = data.get('logout_from_all', False)

#             if not login_input or not password:
#                 logger.warning('Login input and password are required')
#                 return JsonResponse({'error': 'Login input and password are required'}, status=400)

#             try:
#                 if '@' in login_input:
#                     user = User.objects.get(email=login_input)
#                 else:
#                     user = User.objects.get(username=login_input)
#             except User.DoesNotExist:
#                 logger.warning('Username or email not found')
#                 return JsonResponse({'error': 'Username or email not found'}, status=401)

#             if logout_from_all:
#                 UserSession.objects.filter(user=user, active=True).update(active=False)

#             active_session = UserSession.objects.filter(user=user, active=True).first()
#             if active_session and not logout_from_all:
#                 logger.warning('User already logged in with an active session')
#                 return JsonResponse({'error': 'User already logged in'}, status=403)

#             user = authenticate(request, username=user.username, password=password)
#             if user is not None:
#                 login(request, user)
#                 refresh = RefreshToken.for_user(user)
#                 logger.info(f'User {user.username} authenticated successfully')

#                 session_id = get_random_string(length=32)
#                 UserSession.objects.create(user=user, session_id=session_id, email=user.email, active=True)

#                 logger.debug(f'Session created with ID: {session_id}')

#                 encrypted_response = encrypt_data({
#                     'success': 'User authenticated',
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh),
#                     'user_id': user.id,
#                     'session_id': session_id
#                 })

#                 return JsonResponse({'encrypted_content': encrypted_response}, status=200)
#             else:
#                 logger.warning('Password not correct')
#                 return JsonResponse({'error': 'Password not correct'}, status=401)
#         except json.JSONDecodeError:
#             logger.error('Invalid JSON format in request')
#             return JsonResponse({'error': 'Invalid JSON'}, status=400)
#         except Exception as e:
#             logger.error(f'Internal server error: {str(e)}')
#             return JsonResponse({'error': 'Internal server error'}, status=500)
#     else:
#         logger.error('Invalid request method')
#         return JsonResponse({'error': 'Invalid request method'}, status=405)







#Encrypted API to check session status of the user
@csrf_exempt
def check_session_status(request):
    if request.method == 'POST':
        try:
            # Decrypt incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f'Encrypted content received: {encrypted_content}')

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            # Decrypt the content
            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f'Decrypted content: {decrypted_content}')
            data = json.loads(decrypted_content)

            # Extract session ID from the decrypted content
            session_id = data.get('session_id')

            if not session_id:
                logger.warning('Session ID not provided')
                encrypted_response = encrypt_data({'error': 'Session ID not provided'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            session = UserSession.objects.filter(session_id=session_id).first()

            if not session:
                logger.warning('Session not found')
                encrypted_response = encrypt_data({'error': 'Session not found'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=404)

            # Log the session status
            logger.info(f'Session {session_id} status is {session.active}')

            # Encrypt the session status and return it
            encrypted_response = encrypt_data({
                'session_id': session_id,
                'active': session.active
            })
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            encrypted_response = encrypt_data({'error': 'Invalid JSON'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=400)

        except Exception as e:
            logger.error(f'Internal server error: {str(e)}')
            encrypted_response = encrypt_data({'error': 'Internal server error'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=500)

    else:
        logger.error('Invalid request method')
        encrypted_response = encrypt_data({'error': 'Invalid request method'})
        return JsonResponse({'encrypted_content': encrypted_response}, status=405)



#Encrypted API to logout the user from all devices
@csrf_exempt
def logout_from_all_devices(request):
    if request.method == 'POST':
        try:
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)
            
            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f'Decrypted content: {data}')

            login_input = data.get('login_input').lower()
            password = data.get('password')
            
            if not login_input or not password:
                logger.warning('Login input and password are required')
                return JsonResponse({'error': 'Login input and password are required'}, status=400)

            try:
                if '@' in login_input:
                    user = User.objects.get(email=login_input)
                else:
                    user = User.objects.get(username=login_input)
            except User.DoesNotExist:
                logger.warning('Username or email not found')
                return JsonResponse({'error': 'Username or email not found'}, status=401)

            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                # Mark all previous sessions as inactive
                UserSession.objects.filter(user=user, active=True).update(active=False)

                encrypted_response = encrypt_data({
                    'success': 'User logged out from all devices'
                })

                return JsonResponse({'encrypted_content': encrypted_response}, status=200)
            else:
                logger.warning('Password not correct')
                return JsonResponse({'error': 'Password not correct'}, status=401)
        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f'Internal server error: {str(e)}')
            return JsonResponse({'error': 'Internal server error'}, status=500)
    else:
        logger.error('Invalid request method')
        return JsonResponse({'error': 'Invalid request method'}, status=405)


#Only Comment out this code when you want access tokens for testing (in case of postman)
# @csrf_exempt
# def signin(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body.decode('utf-8'))
#             login_input = data.get('login_input').lower()
#             password = data.get('password')
            
#             if not login_input or not password:
#                 logger.warning('Login input and password are required')
#                 return JsonResponse({'error': 'Login input and password are required'}, status=400)

#             try:
#                 if '@' in login_input:
#                     user = User.objects.get(email=login_input)
#                 else:
#                     user = User.objects.get(username=login_input)
#             except User.DoesNotExist:
#                 logger.warning('Username or email not found')
#                 return JsonResponse({'error': 'Username or email not found'}, status=401)

#             user = authenticate(request, username=user.username, password=password)
#             if user is not None:
#                 login(request, user)
#                 # Generate JWT tokens or similar mechanism for authentication
#                 # For example, using Django Rest Framework JWT or similar library
#                 # Here, `RefreshToken` is just a placeholder
#                 refresh = RefreshToken.for_user(user)
#                 logger.info(f'User {user.username} authenticated successfully')

#                 return JsonResponse({
#                     'success': 'User authenticated',
#                     'access': str(refresh.access_token),
#                     'refresh': str(refresh),
#                     'user_id': user.id  # Include user ID in the response
#                 }, status=200)
#             else:
#                 logger.warning('Password not correct')
#                 return JsonResponse({'error': 'Password not correct'}, status=401)
#         except json.JSONDecodeError:
#             logger.error('Invalid JSON format in request')
#             return JsonResponse({'error': 'Invalid JSON'}, status=400)
#         except Exception as e:
#             logger.error(f'Internal server error: {str(e)}')
#             return JsonResponse({'error': 'Internal server error'}, status=500)
#     else:
#         logger.error('Invalid request method')
#         return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def session_logout(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))
            logger.debug(f'Request data: {data}')

            session_id = data.get('session_id')
            if not session_id:
                logger.warning('Session ID is required')
                return JsonResponse({'error': 'Session ID is required'}, status=400)

            session = UserSession.objects.filter(session_id=session_id, active=True).first()
            if session:
                session.active = False
                session.save()
                logger.info(f'Session {session_id} marked as inactive')
                return JsonResponse({'success': 'Logged out successfully'}, status=200)
            else:
                logger.warning(f'Session {session_id} not found or already inactive')
                return JsonResponse({'error': 'Session not found or already inactive'}, status=404)
        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f'Internal server error: {str(e)}')
            return JsonResponse({'error': 'Internal server error'}, status=500)
    else:
        logger.error('Invalid request method')
        return JsonResponse({'error': 'Invalid request method'}, status=405)


#Encrypted API to Reset the user's password
@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f"Encrypted content received: {encrypted_content}")

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                encrypted_response = encrypt_data({'error': 'No encrypted content found in the request.'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f"Decrypted content: {decrypted_content}")
            data = json.loads(decrypted_content)
            
            email = data.get('email')
            otp = data.get('otp')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            if not all([email, otp, new_password, confirm_password]):
                logger.warning('All fields are required')
                encrypted_response = encrypt_data({'error': 'All fields are required'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            if new_password != confirm_password:
                logger.warning('Passwords do not match')
                encrypted_response = encrypt_data({'error': 'Passwords do not match'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            try:
                user = User.objects.get(email=email)
                logger.info(f'User found: {user.username}')
            except User.DoesNotExist:
                logger.warning(f'User with email {email} does not exist')
                encrypted_response = encrypt_data({'error': 'User with this email does not exist'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=404)

            try:
                password_reset_request = PasswordResetRequest.objects.get(user=user, otp=otp)
                logger.info('Password reset request found')
            except PasswordResetRequest.DoesNotExist:
                logger.warning('Invalid OTP')
                encrypted_response = encrypt_data({'error': 'Invalid OTP'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            if password_reset_request.expiry_time < timezone.now():
                logger.warning('OTP has expired')
                encrypted_response = encrypt_data({'error': 'OTP has expired'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            user.set_password(new_password)
            user.save()
            logger.info(f'Password for user {user.username} reset successfully')

            password_reset_request.delete()
            logger.info('Password reset request deleted')

            encrypted_response = encrypt_data({'success': 'Password reset successfully'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request')
            encrypted_response = encrypt_data({'error': 'Invalid JSON format'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            encrypted_response = encrypt_data({'error': str(e)})
            return JsonResponse({'encrypted_content': encrypted_response}, status=500)

    else:
        logger.error('Invalid request method')
        encrypted_response = encrypt_data({'error': 'Invalid request method'})
        return JsonResponse({'encrypted_content': encrypted_response}, status=405)


#Encrypted API For Email Service
@api_view(['POST'])
@permission_classes([IsAuthenticated, HasAPIKey])
def email_generator(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f'Encrypted content received: {encrypted_content}')

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=status.HTTP_400_BAD_REQUEST)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f'Decrypted content: {decrypted_content}')
            data = json.loads(decrypted_content)

            # Extract data from the decrypted content
            purpose = data.get('purpose')
            if purpose == 'Other':
                purpose = data.get('otherPurpose')
            num_words = data.get('num_words')
            subject = data.get('subject')
            rephrase = data.get('rephraseSubject', False)
            to = data.get('to')
            tone = data.get('tone')
            keywords = data.get('keywords', [])
            contextual_background = data.get('contextualBackground')
            call_to_action = data.get('callToAction')
            if call_to_action == 'Other':
                call_to_action = data.get('otherCallToAction')
            additional_details = data.get('additionalDetails')
            priority_level = data.get('priorityLevel')
            closing_remarks = data.get('closingRemarks')

            logger.info(f'Generating email with the following data: {data}')

            generated_content = generate_email(
                purpose, num_words, subject, rephrase, to, tone, keywords,
                contextual_background, call_to_action, additional_details,
                priority_level, closing_remarks
            )

            if generated_content:
                logger.info('Email content generated successfully.')
                # Encrypt the response content
                encrypted_response = encrypt_data({'generated_content': generated_content})
                logger.debug(f'Encrypted response: {encrypted_response}')

                return JsonResponse({'encrypted_content': encrypted_response})
            else:
                logger.error('Failed to generate email content.')
                return JsonResponse({'error': 'Failed to generate email content.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f'Error processing request: {e}')
            return JsonResponse({'error': 'An error occurred while processing the request.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#Encrypted API to translate the the generated content
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def translate_content(request):
    translated_content = None
    error = None
    language = ""

    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f'Encrypted content received: {encrypted_content}')

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f'Decrypted content: {decrypted_content}')
            data = json.loads(decrypted_content)

            generated_content = data.get('generated_content')
            language = data.get('language')

            if not generated_content or not language:
                logger.warning('Both generated_content and language are required fields.')
                return JsonResponse({'error': 'Both generated_content and language are required fields.'}, status=400)

            logger.info(f'Translating content: {generated_content} to language: {language}')
            response = bhashini_translate(generated_content, language)

            if response["status_code"] == 200:
                translated_content = response["translated_content"]
                logger.info('Content translated successfully.')
                # Encrypt the response content
                encrypted_response = encrypt_data({
                    'generated_content': generated_content,
                    'translated_content': translated_content,
                    'selected_language': language
                })
                logger.debug(f'Encrypted response: {encrypted_response}')
                return JsonResponse({'encrypted_content': encrypted_response}, status=200)
            else:
                logger.error('Translation failed with status code: {}'.format(response["status_code"]))
                return JsonResponse({'error': 'Translation failed.'}, status=500)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format in request.')
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
        except ValueError as e:
            logger.warning(f'ValueError: {str(e)}')
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f'Unexpected error: {str(e)}')
            return JsonResponse({'error': str(e)}, status=500)

    logger.error('Method not allowed.')
    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
def translate(request):
    translated_text = None
    error = None
    input_text = ""
    from_language = ""
    to_language = ""

    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            logger.debug(f'Encrypted content received: {encrypted_content}')

            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            logger.debug(f'Decrypted content: {decrypted_content}')
            data = json.loads(decrypted_content)

            input_text = data.get('input_text', '')
            from_language = data.get('from_language', '')
            to_language = data.get('to_language', '')

            if input_text and from_language and to_language:
                try:
                    logger.info(f'Translating text from {from_language} to {to_language}')
                    translated_text = bhashini_translate(input_text, to_language, from_language)
                    translated_text = translated_text["translated_content"]
                    
                    logger.info('Translation successful')
                    logger.debug(f'Input text: {input_text}')
                    logger.debug(f'Translated text: {translated_text}')
                except Exception as e:
                    error = f"Error during translation: {str(e)}"
                    logger.error(error)
            else:
                error = "Please provide the input text and select both languages."
                logger.warning(error)
        except json.JSONDecodeError:
            error = "Invalid JSON format received."
            logger.error(error)
        except Exception as e:
            error = f"Error during request handling: {str(e)}"
            logger.error(error)
    else:
        error = 'Invalid request method'
        logger.warning(error)

    # Prepare the response data
    response_data = {
        'translated_text': translated_text,
        'error': error,
        'input_text': input_text,
        'from_language': from_language,
        'to_language': to_language
    }
    
    # Encrypt the response
    encrypted_response = encrypt_data(response_data)
    logger.debug(f'Encrypted response: {encrypted_response}')
    
    return JsonResponse({'encrypted_content': encrypted_response})


#Encrypted API For Business Proposal Service
# @api_view(['POST'])
# @permission_classes([IsAuthenticated,HasAPIKey])
# def business_proposal_generator(request):
#     if request.method == 'POST':
#         try:
#             # Extract and decrypt the incoming payload
#             encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
#             if not encrypted_content:
#                 logger.warning('No encrypted content found in the request.')
#                 return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

#             decrypted_content = decrypt_data(encrypted_content)
#             data = json.loads(decrypted_content)
#             logger.debug(f'Decrypted content: {data}')

#             business_intro = data.get('businessIntroduction')
#             proposal_objective = data.get('proposalObjective')
#             num_words = data.get('numberOfWords')
#             scope_of_work = data.get('scopeOfWork')
#             project_phases = data.get('projectPhases')
#             expected_outcomes = data.get('expectedOutcomes')
#             tech_innovations = data.get('technologiesAndInnovations')  # Combined field
#             target_audience = data.get('targetAudience')
#             budget_info = data.get('budgetInformation')
#             timeline = data.get('timeline')
#             benefits = data.get('benefitsToRecipient')
#             closing_remarks = data.get('closingRemarks')

#             logger.info('Generating business proposal content.')
#             proposal_content = generate_bus_pro(
#                 business_intro, proposal_objective, num_words, scope_of_work,
#                 project_phases, expected_outcomes, tech_innovations, target_audience,
#                 budget_info, timeline, benefits, closing_remarks
#             )

#             # Encrypt the response content
#             encrypted_content = encrypt_data({'generated_content': proposal_content})
#             logger.info('Business proposal content generated successfully.')

#             return JsonResponse({'encrypted_content': encrypted_content}, status=200)

#         except json.JSONDecodeError:
#             logger.error('Invalid JSON format received.')
#             return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
#         except ValueError as e:
#             logger.error(f'ValueError: {str(e)}')
#             return JsonResponse({'error': str(e)}, status=400)
#         except Exception as e:
#             logger.error(f'Exception: {str(e)}')
#             return JsonResponse({'error': str(e)}, status=500)

#     logger.warning('Method not allowed.')
#     return JsonResponse({'error': 'Method not allowed.'}, status=405)

@api_view(['POST'])
@permission_classes([IsAuthenticated, HasAPIKey])
def business_proposal_generator(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f'Decrypted content: {data}')

            business_intro = data.get('businessIntroduction')
            proposal_objective = data.get('proposalObjective')
            # Handle otherObjective if proposalObjective is 'Others'
            other_objective = data.get('otherObjective')
            if proposal_objective == 'Others' and other_objective:
                proposal_objective = other_objective

            num_words = data.get('numberOfWords')
            scope_of_work = data.get('scopeOfWork')
            project_phases = data.get('projectPhases')
            expected_outcomes = data.get('expectedOutcomes')
            tech_innovations = data.get('technologiesAndInnovations')  # Combined field
            target_audience = data.get('targetAudience')
            budget_info = data.get('budgetInformation')
            timeline = data.get('timeline')
            benefits = data.get('benefitsToRecipient')
            closing_remarks = data.get('closingRemarks')

            logger.info('Generating business proposal content.')
            proposal_content = generate_bus_pro(
                business_intro, proposal_objective, num_words, scope_of_work,
                project_phases, expected_outcomes, tech_innovations, target_audience,
                budget_info, timeline, benefits, closing_remarks
            )

            # Encrypt the response content
            encrypted_content = encrypt_data({'generated_content': proposal_content})
            logger.info('Business proposal content generated successfully.')

            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format received.')
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
        except ValueError as e:
            logger.error(f'ValueError: {str(e)}')
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f'Exception: {str(e)}')
            return JsonResponse({'error': str(e)}, status=500)

    logger.warning('Method not allowed.')
    return JsonResponse({'error': 'Method not allowed.'}, status=405)


#Encrypted API For Offer Letter Service
@api_view(['POST'])
@permission_classes([IsAuthenticated,HasAPIKey])
def offer_letter_generator(request):
    try:
        encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
        if not encrypted_content:
            logger.warning('No encrypted content found in the request.')
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        decrypted_content = decrypt_data(encrypted_content)
        data = json.loads(decrypted_content)
        logger.debug(f'Decrypted content: {data}')

        company_details = data.get('companyDetails')
        candidate_name = data.get('candidateFullName')
        position_title = data.get('positionTitle')
        department = data.get('department')
        status = data.get('status')
        location = data.get('location')
        start_date = data.get('expectedStartDate')
        compensation_benefits = data.get('compensationBenefits')  # Merged field
        work_hours = data.get('workHours')
        terms = data.get('termsConditions')
        acceptance_deadline = data.get('deadline')
        contact_info = data.get('contactInfo')
        documents_needed = data.get('documentsNeeded')
        closing_remarks = data.get('closingRemarks')

        logger.info('Generating offer letter content.')
        offer_letter_content = generate_offer_letter(
            company_details,  candidate_name, position_title, department, status,
            location, start_date, compensation_benefits, work_hours,
            terms, acceptance_deadline, contact_info, documents_needed, closing_remarks
        )

        if offer_letter_content:
            encrypted_content = encrypt_data({'generated_content': offer_letter_content})
            logger.info('Offer letter content generated successfully.')
            return JsonResponse({'encrypted_content': encrypted_content}, status=200)

        logger.error('Failed to generate offer letter content.')
        return JsonResponse({'error': 'Failed to generate offer letter. Please try again.'}, status=500)

    except json.JSONDecodeError:
        logger.error('Invalid JSON format received.')
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except ValueError as e:
        logger.error(f'ValueError: {str(e)}')
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f'Exception: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)

    logger.warning('Method not allowed.')
    return JsonResponse({'error': 'Method not allowed.'}, status=405)



@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile(request):
    user = request.user
    profile = Profile.objects.get(user=user)
    errors = []

    if request.method == 'POST':
        try:
            # Decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f'Decrypted content: {data}')

            # Update user and profile data based on received JSON
            user.first_name = data.get('first_name', user.first_name)
            user.last_name = data.get('last_name', user.last_name)
            user.email = data.get('email', user.email)
            profile.bio = data.get('bio', profile.bio)
            profile.location = data.get('location', profile.location)

            birth_date = data.get('birth_date')
            if birth_date:
                parsed_date = parse_date(birth_date)
                if parsed_date:
                    profile.birth_date = parsed_date
                else:
                    errors.append("Invalid date format for birth date.")
                    profile.birth_date = None

            if not user.first_name:
                errors.append("First name is required.")
            if not user.last_name:
                errors.append("Last name is required.")
            if not user.email:
                errors.append("Email is required.")

            if not errors:
                user.save()
                profile.save()
                response_data = {'message': 'Profile updated successfully.'}
            else:
                response_data = {'errors': errors}

            # Encrypt the response content
            encrypted_response = encrypt_data(response_data)
            logger.info('Profile updated successfully.')

            # Return the encrypted response
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format received.')
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
        except ValueError as e:
            logger.error(f'ValueError: {str(e)}')
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f'Exception: {str(e)}')
            return JsonResponse({'error': str(e)}, status=500)

    # Handle GET request
    response_data = {
        'user': {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email
        },
        'profile': {
            'bio': profile.bio,
            'location': profile.location,
            'birth_date': profile.birth_date.isoformat() if profile.birth_date else None
        }
    }

    # Encrypt the response content
    encrypted_response = encrypt_data(response_data)
    logger.info('Profile data retrieved successfully.')

    # Return the encrypted response
    return JsonResponse({'encrypted_content': encrypted_response})


@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    if request.method == 'POST':
        try:
            # Decrypt incoming request body
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f"Decrypted content: {data}")

            current_password = data.get('current_password')
            new_password = data.get('new_password')
            confirm_new_password = data.get('confirm_new_password')

            # Validate the current password
            if not request.user.check_password(current_password):
                logger.warning(f"User {request.user.username} provided incorrect current password.")
                encrypted_response = encrypt_data({'error': 'Current password is incorrect.'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            # Check if new passwords match
            if new_password != confirm_new_password:
                logger.warning(f"User {request.user.username} provided non-matching new passwords.")
                encrypted_response = encrypt_data({'error': 'New passwords do not match.'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            # Prevent using the same new password as the current password
            if new_password == current_password:
                logger.warning(f"User {request.user.username} attempted to use the same new password as the current password.")
                encrypted_response = encrypt_data({'error': 'New password cannot be the same as the current password.'})
                return JsonResponse({'encrypted_content': encrypted_response}, status=400)

            # Update password
            request.user.set_password(new_password)
            request.user.save()

            # Keep the user logged in after password change
            update_session_auth_hash(request, request.user)
            logger.info(f"User {request.user.username} successfully changed their password.")

            encrypted_response = encrypt_data({'message': 'Password changed successfully.'})
            return JsonResponse({'encrypted_content': encrypted_response})

        except json.JSONDecodeError:
            logger.error("Invalid JSON received.")
            encrypted_response = encrypt_data({'error': 'Invalid JSON.'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=400)

        except Exception as e:
            logger.error(f'Internal server error: {str(e)}')
            encrypted_response = encrypt_data({'error': 'Internal server error.'})
            return JsonResponse({'encrypted_content': encrypted_response}, status=500)

    logger.error("Invalid request method used.")
    encrypted_response = encrypt_data({'error': 'Invalid request method.'})
    return JsonResponse({'encrypted_content': encrypted_response}, status=405)



#Encrypted API For summarize Service
@api_view(['POST'])
@permission_classes([IsAuthenticated, HasAPIKey])
def summarize_document(request):
    try:
        # Extract form data
        document_context = request.data.get('documentContext')
        main_subject = request.data.get('mainSubject')
        summary_purpose = request.data.get('summaryPurpose')
        length_detail = request.data.get('lengthDetail')
        important_elements = request.data.get('importantElements')
        audience = request.data.get('audience')
        tone = request.data.get('tone')
        format_ = request.data.get('format')
        additional_instructions = request.data.get('additionalInstructions')
        document_file = request.FILES.get('documentFile')

        if not document_file:
            return JsonResponse({'error': 'No document file provided.'}, status=400)

        # Generate summary
        summary = generate_summary(
            document_context, main_subject, summary_purpose, length_detail,
            important_elements, audience, tone, format_, additional_instructions, document_file
        )
        # print(document_context)
        # print(main_subject)


        if summary.startswith("Error:"):
            logger.error(summary)
            return JsonResponse({'error': summary}, status=500)

        return JsonResponse({'summary': summary}, status=200)

    except Exception as e:
        logger.error(f'Exception: {str(e)}')
        return JsonResponse({'error': str(e)}, status=500)
    

#Encrypted API For contnet generation Service
@api_view(['POST'])
@permission_classes([IsAuthenticated,HasAPIKey])
def content_generator(request):
    try:
        # Load and decode the request body
        body = request.body.decode('utf-8')
        logger.debug(f"Request body received: {body}")

        # Extract and decrypt the incoming payload
        data = json.loads(body)
        encrypted_content = data.get('encrypted_content')
        if not encrypted_content:
            logger.warning("No encrypted content found in the request.")
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        logger.debug(f"Encrypted content received: {encrypted_content}")

        decrypted_content = decrypt_data(encrypted_content)
        logger.debug(f"Decrypted content: {decrypted_content}")

        data = json.loads(decrypted_content)

        # Extract fields from the decrypted JSON data
        company_info = data.get('company_info')
        content_purpose = data.get('content_purpose')
        desired_action = data.get('desired_action')
        topic_details = data.get('topic_details')
        keywords = data.get('keywords')
        audience_profile = data.get('audience_profile')
        format_structure = data.get('format_structure')
        num_words = data.get('num_words')
        seo_keywords = data.get('seo_keywords')
        references = data.get('references')

        logger.debug(f"Data extracted for content generation: company_info={company_info}, content_purpose={content_purpose}, desired_action={desired_action}")

        # Generate the content
        logger.info("Generating content...")
        content = generate_content(
            company_info,
            content_purpose,
            desired_action,
            topic_details,
            keywords,
            audience_profile,
            format_structure,
            num_words,
            seo_keywords,
            references
        )

        if content:
            logger.info("Content generated successfully.")
            encrypted_response_content = encrypt_data({'generated_content': content})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        logger.error("Failed to generate content.")
        return JsonResponse({'error': 'Failed to generate content. Please try again.'}, status=500)

    except json.JSONDecodeError:
        logger.error("Invalid JSON format received.")
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except ValueError as e:
        logger.error(f"ValueError occurred: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

    logger.error("Method not allowed.")
    return JsonResponse({'error': 'Method not allowed.'}, status=405)

#Encrypted API For sales script Service
@api_view(['POST'])
@permission_classes([IsAuthenticated,HasAPIKey])
def sales_script_generator(request):
    try:
        # Load and decode the request body
        body = request.body.decode('utf-8')
        logger.debug(f"Request body received: {body}")

        # Extract and decrypt the incoming payload
        data = json.loads(body)
        encrypted_content = data.get('encrypted_content')
        if not encrypted_content:
            logger.warning("No encrypted content found in the request.")
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        logger.debug(f"Encrypted content received: {encrypted_content}")

        decrypted_content = decrypt_data(encrypted_content)
        logger.debug(f"Decrypted content: {decrypted_content}")

        data = json.loads(decrypted_content)

        # Extract fields from the decrypted JSON data
        num_words = data.get('num_words')
        company_details = data.get('company_details')
        product_descriptions = data.get('product_descriptions')
        features_benefits = data.get('features_benefits')
        pricing_info = data.get('pricing_info')
        promotions = data.get('promotions')
        target_audience = data.get('target_audience')
        sales_objectives = data.get('sales_objectives')
        competitive_advantage = data.get('competitive_advantage')
        compliance = data.get('compliance')

        logger.debug(f"Data extracted for sales script generation: num_words={num_words}, company_details={company_details}")

        # Generate the sales script
        logger.info("Generating sales script...")
        sales_script = generate_sales_script(
            company_details,
            num_words,
            product_descriptions,
            features_benefits,
            pricing_info,
            promotions,
            target_audience,
            sales_objectives,
            competitive_advantage,
            compliance,
        )

        if sales_script:
            logger.info("Sales script generated successfully.")
            encrypted_response_content = encrypt_data({'generated_content': sales_script})
            return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

        logger.error("Failed to generate sales script.")
        return JsonResponse({'error': 'Failed to generate sales script. Please try again.'}, status=500)

    except json.JSONDecodeError:
        logger.error("Invalid JSON format received.")
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except ValueError as e:
        logger.error(f"ValueError occurred: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

    logger.error("Method not allowed.")
    return JsonResponse({'error': 'Method not allowed.'}, status=405)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        # Fetch the active session for the logged-in user
        user_session = UserSession.objects.filter(user=request.user, active=True).first()

        if user_session:
            # Set the active field to False
            user_session.active = False
            user_session.save()

        # Perform Django logout operation
        logout(request)
        logger.info(f"User {request.user.username} logged out successfully.")
        return JsonResponse({'success': 'Logged out successfully'}, status=200)
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return JsonResponse({'error': 'An error occurred during logout.'}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_presentation(request):
    try:
        # Handle the multipart form data
        encrypted_content = request.POST.get('encrypted_content')
        if not encrypted_content:
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        # Decrypt the content
        decrypted_content = decrypt_data(encrypted_content)

        # Parse decrypted JSON data
        data = json.loads(decrypted_content)

        # Extract fields from the decrypted data
        title = data.get('title')
        num_slides = data.get('num_slides')
        bg_image_path = request.FILES.get('background_image')  # bg_image as a file
        document = request.FILES.get('document')  # document as a file

        if not title or not num_slides:
            return JsonResponse({'error': 'Title and number of slides are required.'}, status=400)

        # Handle document content optionally (assuming `extract_document_content` processes the file)
        document_content = extract_document_content(document) if document else ""

        # Generate presentation logic
        prs = Presentation()
        slide_titles = generate_slide_titles(document_content, num_slides, None, title)
        slide_titles = slide_titles.replace('[', '').replace(']', '').replace('"', '').split(',')

        for st in slide_titles:
            slide_content = generate_slide_content(document_content, st, None).replace("*", '').split('\n')
            current_content = [point.strip() for point in slide_content if len(point.strip()) > 0]

            if len(current_content) > 4:
                current_content = current_content[:4]  # Limit to only 4 points

            add_slide(prs, st.strip(), current_content, bg_image_path)

        # Save presentation to a BytesIO object
        buffer = io.BytesIO()
        prs.save(buffer)
        buffer.seek(0)  # Rewind the buffer

        # Return file response
        response = FileResponse(buffer, as_attachment=True, filename='SmartOffice_Assistant_Presentation.pptx')
        return response

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


#Encrypted API For generate blog Service
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_blog_view(request):
    try:
        # Load and decode the request body
        body = request.body.decode('utf-8')
        logger.debug(f"Request body received: {body}")

        # Extract and decrypt the incoming payload
        data = json.loads(body)
        encrypted_content = data.get('encrypted_content')
        if not encrypted_content:
            logger.warning("No encrypted content found in the request.")
            return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

        logger.debug(f"Encrypted content received: {encrypted_content}")
        decrypted_content = decrypt_data(encrypted_content)
        logger.debug(f"Decrypted content: {decrypted_content}")

        data = json.loads(decrypted_content)

        # Extract the required fields
        title = data.get('title')
        tone = data.get('tone')
        keywords = data.get('keywords', None)  # Optional

        # Ensure required fields are present
        if not title or not tone:
            return JsonResponse({"error": "Missing 'title' or 'tone'."}, status=400)

        # Call the generate_blog function
        blog_content = generate_blog(title, tone, keywords)

        # Encrypt the response content
        encrypted_response_content = encrypt_data({'blog_content': blog_content})

        # Return the encrypted blog content as a JSON response
        return JsonResponse({'encrypted_content': encrypted_response_content}, status=200)

    except json.JSONDecodeError:
        logger.error("Invalid JSON format received.")
        return JsonResponse({"error": "Invalid JSON format. Please provide valid JSON data."}, status=400)
    except ValueError as e:
        logger.error(f"ValueError occurred: {str(e)}")
        return JsonResponse({"error": str(e)}, status=400)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

    # If not a POST request, return an error
    return JsonResponse({"error": "Only POST method is allowed."}, status=405)


#Encrypted API For rephrase Service
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def rephrasely_view(request):
    if request.method == 'POST':
        try:
            # Extract and decrypt the incoming payload
            encrypted_content = json.loads(request.body.decode('utf-8')).get('encrypted_content')
            if not encrypted_content:
                logger.warning('No encrypted content found in the request.')
                return JsonResponse({'error': 'No encrypted content found in the request.'}, status=400)

            # Decrypt the content
            decrypted_content = decrypt_data(encrypted_content)
            data = json.loads(decrypted_content)
            logger.debug(f'Decrypted content: {data}')

            # Extract required fields
            text_to_rephrase = data.get('text_to_rephrase')
            tone = data.get('tone')
            target_audience = data.get('target_audience')
            num_words = data.get('num_words', "default")  # Optional, default is "default"

            # Call the rephrasely function
            rephrased_text = rephrasely(text_to_rephrase, tone, target_audience, num_words)

            # Encrypt the response content
            encrypted_response = encrypt_data({'rephrased_text': rephrased_text})
            logger.info('Rephrased content generated successfully.')

            # Return the encrypted response
            return JsonResponse({'encrypted_content': encrypted_response}, status=200)

        except json.JSONDecodeError:
            logger.error('Invalid JSON format received.')
            return JsonResponse({'error': 'Invalid JSON format. Please provide valid JSON data.'}, status=400)
        except ValueError as e:
            logger.error(f'ValueError: {str(e)}')
            return JsonResponse({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f'Exception: {str(e)}')
            return JsonResponse({'error': str(e)}, status=500)

    logger.warning('Method not allowed.')
    return JsonResponse({'error': 'Method not allowed.'}, status=405)





# List of greetings
GREETING_MESSAGES = [
    "Hey there! 👋 I’m Advika, your friendly AI champion. Got a question about our AI services? Let’s brighten your day with the perfect solution! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Greetings, human! I’m Advika, your digital assistant built for speed ⚡. Ask me anything about our AI services, and let’s get things done in a flash! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hello and welcome! 🌟 I’m Advika, here to assist with all your AI-related queries. What’s on your mind? Let’s dive into our exciting services together! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hi there! I’m Advika, your guide to exploring the world of AI. Have a question about our services? Let’s explore it together—just ask away! 🤔 You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hello, superstar! 🌟 I’m Advika, your AI sidekick. Curious about our amazing AI services? I’ve got all the answers, let’s get started! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "✨ Welcome, adventurer! ✨ I’m Advika, your AI guide on this exciting journey. Ask me about any of our cutting-edge AI services, and let’s unlock some magic together! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hey! I’m Advika, here to support you on your AI journey. Got questions about our services? Don’t worry, we’ll tackle them together—let’s get started! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hi there! ⏱ I’m Advika, and I’m here to help you quickly explore our AI services. Ask away, and I’ll provide the answers in no time! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Greetings! I’m Advika, your dedicated AI assistant. Have any questions about our AI offerings? I’m here to guide you—how may I assist you today? You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk).",
    "Hey, awesome human! 🎉 I’m Advika, your go-to AI for all things related to our services. Got a question? Let’s make it happen—go champion! You can also check out our [Resource Hub here](https://prodigidesk.ai/ProdigiDesk)."
]


# GREETING_MESSAGES = [
#     "Hey there! 👋 I’m Advika, your friendly AI champion. Got a question about our AI services? Let’s brighten your day with the perfect solution!",
#     "Greetings, human! I’m Advika, your digital assistant built for speed ⚡. Ask me anything about our AI services, and let’s get things done in a flash!",
#     "Hello and welcome! 🌟 I’m Advika, here to assist with all your AI-related queries. What’s on your mind? Let’s dive into our exciting services together!",
#     "Hi there! I’m Advika, your guide to exploring the world of AI. Have a question about our services? Let’s explore it together—just ask away! 🤔",
#     "Hello, superstar! 🌟 I’m Advika, your AI sidekick. Curious about our amazing AI services? I’ve got all the answers, let’s get started!",
#     "✨ Welcome, adventurer! ✨ I’m Advika, your AI guide on this exciting journey. Ask me about any of our cutting-edge AI services, and let’s unlock some magic together!",
#     "Hey! I’m Advika, here to support you on your AI journey. Got questions about our services? Don’t worry, we’ll tackle them together—let’s get started!",
#     "Hi there! ⏱ I’m Advika, and I’m here to help you quickly explore our AI services. Ask away, and I’ll provide the answers in no time!",
#     "Greetings! I’m Advika, your dedicated AI assistant. Have any questions about our AI offerings? I’m here to guide you—how may I assist you today?",
#     "Hey, awesome human! 🎉 I’m Advika, your go-to AI for all things related to our services. Got a question? Let’s make it happen—go champion!"
# ]
 



@api_view(['GET','POST'])
@permission_classes([])
def chatbot_view(request):
    if settings.FAISS_VECTOR_STORE is None:
        return JsonResponse({"error": "Vector store not initialized"}, status=500)

    if request.method == 'GET':
        # Randomly select a greeting message
        greeting_message = random.choice(GREETING_MESSAGES)
        return JsonResponse({'answer': greeting_message}, status=200)
 
    elif request.method == 'POST':
        try:
            # Decrypt or read the incoming data (handling encrypted payloads if needed)
            data = json.loads(request.body)
            question = data.get('question')
 
            if not question:
                return JsonResponse({'error': 'No question provided.'}, status=400)
 
            # Handle user input (follow-up question)
            result = ask_question_chatbot(question)
 
            return JsonResponse({'answer': result}, status=200)
 
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
 
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
 
 
@api_view(['POST'])
@permission_classes([])
def speech_api(request):
    if request.method == 'POST':
        try:
            # Parse the JSON data from the request body
            data = json.loads(request.body)
            text = data.get('text', 'No text provided')
           
            # Generate speech from text using gTTS
            tts = gTTS(text=text, lang='en', slow=False)
 
            # In-memory file object for the audio
            mp3_fp = io.BytesIO()
            tts.write_to_fp(mp3_fp)
 
            mp3_fp.seek(0)  # Reset the pointer to the beginning of the file
 
            # Prepare the HTTP response with the audio file
            response = HttpResponse(mp3_fp, content_type='audio/mpeg')
            response['Content-Disposition'] = 'attachment; filename="speech.mp3"'
 
            return response
       
        except Exception as e:
            # Handle any exception and return error message
            return JsonResponse({'status': 'error', 'message': str(e)})
   
    else:
        # Handle non-POST requests
        return JsonResponse({'status': 'error', 'message': 'Only POST requests are allowed.'})