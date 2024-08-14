import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from django.test import Client
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from django.core import mail
from django.test import Client
from django.utils import timezone
from django.conf import settings
import pytest
from django.urls import reverse
from django.contrib.auth.models import User
from django.core import mail
from django.core.mail import BadHeaderError
from django.test import Client
from django.utils import timezone
from django.conf import settings
from unittest.mock import patch
import json

from unittest.mock import patch
import json

from core.models import PasswordResetRequest

# Define your Base64 encoded AES keys and IVs
AES_IV_b64 = "KRP1pDpqmy2eJos035bxdg=="
AES_SECRET_KEY_b64 = "HOykfyW56Uesby8PTgxtSA=="
ENCRYPTION_IV_b64 = "3G1Nd0j0l5BdPmJh01NrYg=="
ENCRYPTION_SECRET_KEY_b64 = "XGp3hFq56Vdse3sLTtXyQQ=="

# Decode Base64 strings to bytes
AES_IV = base64.b64decode(AES_IV_b64)
AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY_b64)
ENCRYPTION_IV = base64.b64decode(ENCRYPTION_IV_b64)
ENCRYPTION_SECRET_KEY = base64.b64decode(ENCRYPTION_SECRET_KEY_b64)

# Ensure IV is 16 bytes long (128 bits)
if len(AES_IV) != 16:
    raise ValueError("AES IV must be 16 bytes long")
if len(ENCRYPTION_IV) != 16:
    raise ValueError("Encryption IV must be 16 bytes long")

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

@pytest.mark.django_db
class TestAddUser:
    @pytest.fixture
    def client(self):
        return Client()

    @pytest.fixture
    def url(self):
        return reverse('add_user')

    def test_valid_request(self, client, url):
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'StrongPassword123!',
            'confirm_password': 'StrongPassword123!'
        }
        encrypted_data = encrypt_data(data)
        response = client.post(url, json.dumps({'encrypted_content': encrypted_data}), content_type='application/json')
        assert response.status_code == 201
        assert 'encrypted_content' in response.json()

    def test_missing_encrypted_content(self, client, url):
        response = client.post(url, json.dumps({}), content_type='application/json')
        assert response.status_code == 400
        assert response.json()['error'] == 'No encrypted content found in the request.'

    def test_invalid_json_format(self, client, url):
        response = client.post(url, 'invalid-json', content_type='application/json')
        assert response.status_code == 400
        assert response.json()['error'] == 'Invalid JSON format.'

    def test_decrypted_content_missing_fields(self, client, url):
        data = {'username': 'testuser'}
        encrypted_data = encrypt_data(data)
        response = client.post(url, json.dumps({'encrypted_content': encrypted_data}), content_type='application/json')
        assert response.status_code == 400
        assert response.json()['error'] == 'All fields are required.'

    def test_passwords_do_not_match(self, client, url):
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password123',
            'confirm_password': 'password1234'
        }
        encrypted_data = encrypt_data(data)
        response = client.post(url, json.dumps({'encrypted_content': encrypted_data}), content_type='application/json')
        assert response.status_code == 400
        assert response.json()['error'] == 'Passwords do not match.'

    def test_weak_password(self, client, url):
        data = {
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': '123',
            'confirm_password': '123'
        }
        encrypted_data = encrypt_data(data)
        response = client.post(url, json.dumps({'encrypted_content': encrypted_data}), content_type='application/json')
        assert response.status_code == 400
        assert 'error' in response.json()

    def test_username_already_taken(self, client, url):
        User.objects.create_user(username='testuser', email='testuser1@example.com', password='password123')
        data = {
            'username': 'testuser',
            'email': 'testuser2@example.com',
            'password': 'StrongPassword123!',
            'confirm_password': 'StrongPassword123!'
        }
        encrypted_data = encrypt_data(data)
        response = client.post(url, json.dumps({'encrypted_content': encrypted_data}), content_type='application/json')
        assert response.status_code == 400
        assert response.json()['error'] == 'Username is already taken.'

@pytest.mark.django_db
class TestSendOTP:
    @pytest.fixture
    def client(self):
        return Client()

    @pytest.fixture
    def url(self):
        return reverse('send_otp')

    @pytest.fixture
    def user(self):
        return User.objects.create_user(username='testuser', email='testuser@example.com', password='password123')

    def test_send_otp_success(self, client, url, user):
        with patch('core.views.generate_otp', return_value='123456'):
            response = client.post(url, json.dumps({'email': user.email}), content_type='application/json')

        assert response.status_code == 200
        assert response.json()['success'] == 'OTP sent successfully'

        # Check that OTP is stored in the database
        password_reset_request = PasswordResetRequest.objects.get(user=user)
        assert password_reset_request.otp == '123456'
        assert password_reset_request.expiry_time > timezone.now()

        # Check that an email was sent
        assert len(mail.outbox) == 1
        assert mail.outbox[0].subject == 'Password Reset OTP'
        assert 'Your OTP for password reset is 123456' in mail.outbox[0].body
        assert mail.outbox[0].to == [user.email]

    def test_email_does_not_exist(self, client, url):
        response = client.post(url, json.dumps({'email': 'nonexistent@example.com'}), content_type='application/json')

        assert response.status_code == 404
        assert response.json()['error'] == 'Email does not exist'

    def test_invalid_request_method(self, client, url):
        response = client.get(url)

        assert response.status_code == 405
        assert response.json()['error'] == 'Invalid request method'

    def test_error_sending_email(self, client, url, user):
        with patch('core.views.send_mail', side_effect=Exception('SMTP Error')):
            response = client.post(url, json.dumps({'email': user.email}), content_type='application/json')

        assert response.status_code == 500
        assert response.json()['error'] == 'Error sending email: SMTP Error'

        # Check that OTP is still stored in the database
        password_reset_request = PasswordResetRequest.objects.filter(user=user).exists()
        assert not password_reset_request

@pytest.mark.django_db
class TestForgotPassword:
    @pytest.fixture
    def client(self):
        return Client()

    @pytest.fixture
    def url(self):
        return reverse('forgot_password')

    @pytest.fixture
    def user(self):
        return User.objects.create_user(username='testuser', email='testuser@example.com', password='password123')

    def test_forgot_password_success(self, client, url, user):
        with patch('core.views.generate_otp', return_value='123456'):
            response = client.post(url, json.dumps({'email': user.email}), content_type='application/json')

        assert response.status_code == 200
        assert response.json()['success'] == 'OTP sent successfully'

        # Check that OTP is stored in the database
        password_reset_request = PasswordResetRequest.objects.get(user=user)
        assert password_reset_request.otp == '123456'
        assert password_reset_request.expiry_time > timezone.now()

        # Check that an email was sent
        assert len(mail.outbox) == 1
        assert mail.outbox[0].subject == 'Password Reset OTP'
        assert 'Your OTP for password reset is 123456' in mail.outbox[0].body
        assert mail.outbox[0].to == [user.email]

    def test_email_does_not_exist(self, client, url):
        response = client.post(url, json.dumps({'email': 'nonexistent@example.com'}), content_type='application/json')

        assert response.status_code == 404
        assert response.json()['error'] == 'Email does not exist'

    def test_invalid_request_method(self, client, url):
        response = client.get(url)

        assert response.status_code == 405
        assert response.json()['error'] == 'Method "GET" not allowed.'

    def test_invalid_header_error(self, client, url, user):
        with patch('core.views.send_mail', side_effect=BadHeaderError('Invalid header')):
            response = client.post(url, json.dumps({'email': user.email}), content_type='application/json')

        assert response.status_code == 400
        assert response.json()['error'] == 'Invalid header found.'

        # Check that OTP is not stored in the database if email sending fails
        password_reset_request = PasswordResetRequest.objects.filter(user=user).exists()
        assert not password_reset_request

    def test_error_sending_email(self, client, url, user):
        with patch('core.views.send_mail', side_effect=Exception('SMTP Error')):
            response = client.post(url, json.dumps({'email': user.email}), content_type='application/json')

        assert response.status_code == 500
        assert response.json()['error'] == 'Error sending email: SMTP Error'

        # Check that OTP is not stored in the database if email sending fails
        password_reset_request = PasswordResetRequest.objects.filter(user=user).exists()
        assert not password_reset_request



