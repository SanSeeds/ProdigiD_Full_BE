from django.contrib import admin
from .models import Profile, PasswordResetRequest, UserService

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'bio', 'location', 'birth_date', 'valid_from', 'valid_till')

@admin.register(PasswordResetRequest)
class PasswordResetRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'expiry_time', 'is_valid')

@admin.register(UserService)
class UserServiceAdmin(admin.ModelAdmin):
    list_display = ('user', 'email_service', 'offer_letter_service', 'business_proposal_service', 
                    'sales_script_service', 'content_generation_service', 'summarize_service', 
                    'ppt_generation_service')
