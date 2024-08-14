from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from dateutil.relativedelta import relativedelta

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=30, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    valid_from = models.DateField(null=True, blank=True)
    valid_till = models.DateField(null=True, blank=True)

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

class UserService(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(max_length=254, blank=True)
    email_service = models.BooleanField(default=False)
    offer_letter_service = models.BooleanField(default=False)
    business_proposal_service = models.BooleanField(default=False)
    sales_script_service = models.BooleanField(default=False)
    content_generation_service = models.BooleanField(default=False)
    summarize_service = models.BooleanField(default=False)
    ppt_generation_service = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # Ensure email is set from the user object
        if not self.email:
            self.email = self.user.email
        super(UserService, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.username} - Services'
    

class UserSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_id = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)