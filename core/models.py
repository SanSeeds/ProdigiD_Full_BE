from datetime import timedelta
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from dateutil.relativedelta import relativedelta

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

# class UserService(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     email_service = models.BooleanField(default=False)
#     offer_letter_service = models.BooleanField(default=False)
#     business_proposal_service = models.BooleanField(default=False)
#     sales_script_service = models.BooleanField(default=False)
#     content_generation_service = models.BooleanField(default=False)
#     summarize_service = models.BooleanField(default=False)
#     ppt_generation_service = models.BooleanField(default=False)

#     def __str__(self):
#         return f'{self.user.username} - Services'

# class UserService(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     email = models.EmailField(max_length=254, blank=True)
#     email_service = models.BooleanField(default=False)
#     offer_letter_service = models.BooleanField(default=False)
#     business_proposal_service = models.BooleanField(default=False)
#     sales_script_service = models.BooleanField(default=False)
#     content_generation_service = models.BooleanField(default=False)
#     summarize_service = models.BooleanField(default=False)
#     ppt_generation_service = models.BooleanField(default=False)

#     def save(self, *args, **kwargs):
#         # Ensure email is set from the user object
#         if not self.email:
#             self.email = self.user.email
#         super(UserService, self).save(*args, **kwargs)

#     def __str__(self):
#         return f'{self.user.username} - Services'
    


# class UserService(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     email = models.EmailField(max_length=254, blank=True)
    
#     # Service flags
#     email_service = models.BooleanField(default=False)
#     offer_letter_service = models.BooleanField(default=False)
#     business_proposal_service = models.BooleanField(default=False)
#     sales_script_service = models.BooleanField(default=False)
#     content_generation_service = models.BooleanField(default=False)
#     summarize_service = models.BooleanField(default=False)
#     ppt_generation_service = models.BooleanField(default=False)
    
#     # Subscription end dates
#     email_end_date = models.DateField(null=True, blank=True)
#     offer_letter_end_date = models.DateField(null=True, blank=True)
#     business_proposal_end_date = models.DateField(null=True, blank=True)
#     sales_script_end_date = models.DateField(null=True, blank=True)
#     content_generation_end_date = models.DateField(null=True, blank=True)
#     summarize_end_date = models.DateField(null=True, blank=True)
#     ppt_generation_end_date = models.DateField(null=True, blank=True)

#     def save(self, *args, **kwargs):
#         # Set email from the user object if not already set
#         if not self.email:
#             self.email = self.user.email
        
#         # Check each service and set end dates if the service is activated
#         current_date = timezone.now().date()
#         expiration_date = current_date + timedelta(days=30)
        
#         if self.email_service and self.email_end_date is None:
#             self.email_end_date = expiration_date
#         if self.offer_letter_service and self.offer_letter_end_date is None:
#             self.offer_letter_end_date = expiration_date
#         if self.business_proposal_service and self.business_proposal_end_date is None:
#             self.business_proposal_end_date = expiration_date
#         if self.sales_script_service and self.sales_script_end_date is None:
#             self.sales_script_end_date = expiration_date
#         if self.content_generation_service and self.content_generation_end_date is None:
#             self.content_generation_end_date = expiration_date
#         if self.summarize_service and self.summarize_end_date is None:
#             self.summarize_end_date = expiration_date
#         if self.ppt_generation_service and self.ppt_generation_end_date is None:
#             self.ppt_generation_end_date = expiration_date

#         # Save the instance
#         super(UserService, self).save(*args, **kwargs)

#     def __str__(self):
#         return f'{self.user.username} - Services'

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




# class UserSession(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     session_id = models.CharField(max_length=255, unique=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     active = models.BooleanField(default=True)

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
    

class Payment(models.Model):
    order_id = models.CharField(max_length=255, unique=True)
    payment_id = models.CharField(max_length=255, null=True, blank=True)  # To store payment_id
    signature = models.CharField(max_length=255, null=True, blank=True)  # To store signature
    email = models.EmailField(null=True, blank=True)  # To store user email
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10)
    payment_capture = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    verified = models.BooleanField(default=False)  # To store verification status

    def __str__(self):
        return f"Order {self.order_id} - {self.amount} {self.currency}"