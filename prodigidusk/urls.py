from django.contrib import admin
from django.urls import path
from core import views

urlpatterns = [
    path('', views.landing, name='landing'),
    path('about/', views.about, name='about'),
    path('admin/', admin.site.urls),
    path('test_report/', views.test_report, name='test_report'),
    path('signin/', views.signin, name='signin'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('email_generator/', views.email_generator, name='email_generator'),
    path('business_proposal_generator/', views.business_proposal_generator, name='business_proposal_generator'),
    path('offer_letter_generator/', views.offer_letter_generator, name='offer_letter_generator'),
    path('sales_script_generator/', views.sales_script_generator, name='sales_script_generator'),
    path('summarize_document/', views.summarize_document, name='summarize_document'),
    path('content_generator/', views.content_generator, name='content_generator'),
    path('translate_content/', views.translate_content, name='translate_content'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('translate/', views.translate, name='translate'),
    path('change_password/', views.change_password, name='change_password'),
    path('send_otp/', views.send_otp, name='send_otp'),
    path('add_user/', views.add_user, name='add_user'),
    # path('add_user/', views.SignUpView.as_view(), name='add_user'),
    path('complete_registration/', views.complete_registration, name='complete_registration'),
    path('create_presentation/', views.create_presentation, name='create_presentation'),
    
    path('save_selected_services/', views.save_selected_services, name='save_selected_services'),
    # path('get_user_services/<int:user_id>/', views.get_user_services, name='get_user_services'),
        path('get_user_services/<str:email>/', views.get_user_services, name='get_user_services'),

    path('update_services/', views.update_user_services, name='update_user_services'),



]

