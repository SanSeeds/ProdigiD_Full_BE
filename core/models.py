from datetime import timedelta
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from dateutil.relativedelta import relativedelta
import uuid

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=30, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    # valid_from = models.DateField(null=True, blank=True)
    # valid_till = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.user.username


class PasswordResetRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    expiry_time = models.DateTimeField()

    def is_valid(self):
        return timezone.now() < self.expiry_time



class UserService(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254, blank=True)
    
    # Service flags
    email_service = models.BooleanField(default=False)
    offer_letter_service = models.BooleanField(default=False)
    business_proposal_service = models.BooleanField(default=False)
    sales_script_service = models.BooleanField(default=False)
    content_generation_service = models.BooleanField(default=False)
    summarize_service = models.BooleanField(default=False)
    ppt_generation_service = models.BooleanField(default=False)
    blog_generation_service = models.BooleanField(default=False)
    rephrasely_service = models.BooleanField(default=False)
    
    # Subscription end dates
    email_end_date = models.DateField(null=True, blank=True)
    offer_letter_end_date = models.DateField(null=True, blank=True)
    business_proposal_end_date = models.DateField(null=True, blank=True)
    sales_script_end_date = models.DateField(null=True, blank=True)
    content_generation_end_date = models.DateField(null=True, blank=True)
    summarize_end_date = models.DateField(null=True, blank=True)
    ppt_generation_end_date = models.DateField(null=True, blank=True)
    blog_generation_end_date = models.DateField(null=True, blank=True)
    rephrasely_end_date = models.DateField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # Set email from the user object if not already set
        if not self.email:
            self.email = self.user.email
        
        # Check each service and set end dates if the service is activated
        current_date = timezone.now().date()
        expiration_date = current_date + timedelta(days=30)
        
        if self.email_service and self.email_end_date is None:
            self.email_end_date = expiration_date
        if self.offer_letter_service and self.offer_letter_end_date is None:
            self.offer_letter_end_date = expiration_date
        if self.business_proposal_service and self.business_proposal_end_date is None:
            self.business_proposal_end_date = expiration_date
        if self.sales_script_service and self.sales_script_end_date is None:
            self.sales_script_end_date = expiration_date
        if self.content_generation_service and self.content_generation_end_date is None:
            self.content_generation_end_date = expiration_date
        if self.summarize_service and self.summarize_end_date is None:
            self.summarize_end_date = expiration_date
        if self.ppt_generation_service and self.ppt_generation_end_date is None:
            self.ppt_generation_end_date = expiration_date
        if self.blog_generation_service and self.blog_generation_end_date is None:
            self.blog_generation_end_date = expiration_date
        if self.rephrasely_service and self.rephrasely_end_date is None:
            self.rephrasely_end_date = expiration_date

        # Save the instance
        super(UserService, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.username} - Services'


class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_id = models.CharField(max_length=255, unique=True)
    email = models.EmailField()  # New field to store the user's email
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)


class EmailVerificationOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='email_verification_otp')
    otp = models.CharField(max_length=6)
    expiry_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_otp_expired(self):
        """
        Checks if the OTP has expired.
        """
        return timezone.now() > self.expiry_time

    def __str__(self):
        return f"OTP for {self.user.email} - {'Expired' if self.is_otp_expired() else 'Valid'}"
    

class TemporaryEmailVerificationOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    expiry_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_otp_expired(self):
        return timezone.now() > self.expiry_time

    def __str__(self):
        return f"OTP for {self.email} - {'Expired' if self.is_otp_expired() else 'Valid'}"
    
 

# class Payment(models.Model):
#     order_id = models.CharField(max_length=255, unique=True)
#     payment_id = models.CharField(max_length=255, null=True, blank=True)
#     signature = models.CharField(max_length=255, null=True, blank=True)
#     email = models.EmailField(null=True, blank=True)
#     amount = models.DecimalField(max_digits=10, decimal_places=2)
#     currency = models.CharField(max_length=10)
#     payment_capture = models.BooleanField(default=False)
#     created_at = models.DateTimeField(auto_now_add=True)
#     verified = models.BooleanField(default=False)
    
#     # New field to associate the payment with a service
#     # service = models.ForeignKey(UserService, on_delete=models.CASCADE, null=True, blank=True)

#     def __str__(self):
#         return f"Order {self.order_id} - {self.amount} {self.currency}"




class Payment(models.Model):
    order_id = models.CharField(max_length=255, unique=True)
    payment_id = models.CharField(max_length=255, null=True, blank=True)
    signature = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10)
    payment_capture = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)  # When the record was created
    verified = models.BooleanField(default=False)
    
    # New fields
    order_datetime = models.DateTimeField(null=True, blank=True)  # When the order was placed
    subscribed_services = models.JSONField(null=True, blank=True)  # Stores service details as a JSON object
    service = models.ForeignKey('UserService', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"Order {self.order_id} - {self.amount} {self.currency}"
    
# class GuestLogin(models.Model):
#     mobile_number = models.CharField(max_length=15, unique=True)  # Ensure mobile number is unique
#     otp = models.CharField(max_length=6)
#     session_id = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
#     logged_in_at = models.DateTimeField(auto_now_add=True)
#     valid_till = models.DateTimeField()
#     is_active = models.BooleanField(default=True)

#     def is_valid(self):
#         return timezone.now() < self.valid_till

#     def deactivate_session(self):
#         self.is_active = False
#         self.save()

#     def __str__(self):
#         return f"Guest {self.mobile_number} - Session ID {self.session_id} - Active: {self.is_active}"

class GuestLogin(models.Model):
    email = models.EmailField(max_length=255, unique=True)  # Ensure email is unique
    otp = models.CharField(max_length=6)
    session_id = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
    logged_in_at = models.DateTimeField(auto_now_add=True)
    valid_till = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    def is_valid(self):
        return timezone.now() < self.valid_till

    def deactivate_session(self):
        self.is_active = False
        self.save()

    def __str__(self):
        return f"Guest {self.email} - Session ID {self.session_id} - Active: {self.is_active}"




class Cart(models.Model):
    email = models.EmailField(max_length=254, blank=False, unique=True)  # Email is unique
    
    # Service flags with IDs
    email_service = models.BooleanField(default=False)
    offer_letter_service = models.BooleanField(default=False)
    business_proposal_service = models.BooleanField(default=False)
    sales_script_service = models.BooleanField(default=False)
    content_generation_service = models.BooleanField(default=False)
    summarize_service = models.BooleanField(default=False)
    ppt_generation_service = models.BooleanField(default=False)
    blog_generation_service = models.BooleanField(default=False)
    rephrasely_service = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)  # Track when the cart was created
    updated_at = models.DateTimeField(auto_now=True)      # Track when the cart was last updated

    SERVICE_IDS = {
        "email_service": 1,
        "offer_letter_service": 2,
        "business_proposal_service": 3,
        "sales_script_service": 4,
        "content_generation_service": 5,
        "summarize_service": 6,
        "ppt_generation_service": 7,
        "blog_generation_service": 9,
        "rephrasely_service": 10,
    }

    def __str__(self):
        return f"Cart for {self.email} - Services: {self.get_active_services()}"

    def get_active_services(self):
        """
        Return a list of active (True) services in the cart along with their IDs.
        """
        services = []
        if self.email_service:
            services.append({"id": self.SERVICE_IDS["email_service"], "name": "Email Service"})
        if self.offer_letter_service:
            services.append({"id": self.SERVICE_IDS["offer_letter_service"], "name": "Offer Letter Service"})
        if self.business_proposal_service:
            services.append({"id": self.SERVICE_IDS["business_proposal_service"], "name": "Business Proposal Service"})
        if self.sales_script_service:
            services.append({"id": self.SERVICE_IDS["sales_script_service"], "name": "Sales Script Service"})
        if self.content_generation_service:
            services.append({"id": self.SERVICE_IDS["content_generation_service"], "name": "Content Generation Service"})
        if self.summarize_service:
            services.append({"id": self.SERVICE_IDS["summarize_service"], "name": "Summarize Service"})
        if self.ppt_generation_service:
            services.append({"id": self.SERVICE_IDS["ppt_generation_service"], "name": "PPT Generation Service"})
        if self.blog_generation_service:
            services.append({"id": self.SERVICE_IDS["blog_generation_service"], "name": "Blog Generation Service"})
        if self.rephrasely_service:
            services.append({"id": self.SERVICE_IDS["rephrasely_service"], "name": "Rephrasely Service"})
        return services
