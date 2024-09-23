from django.contrib import admin
from django.urls import path
from core import views

urlpatterns = [
    path('', views.landing, name='landing'),
    path('about/', views.about, name='about'),
    path('admin/', admin.site.urls),
    path('test_report/', views.test_report, name='test_report'),
    path('signin/', views.signin, name='signin'),
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
    path('create_presentation/', views.create_presentation, name='create_presentation'),
    path('save_selected_services/', views.save_selected_services, name='save_selected_services'),
    path('get_user_services/<str:email>/', views.get_user_services, name='get_user_services'),
    path('update_services/', views.update_user_services, name='update_user_services'),
    path('logout_from_all_devices/', views.logout_from_all_devices, name='logout_from_all_devices'),
    path('check_session_status/', views.check_session_status, name='check_session_status'),
    path('session_logout/', views.session_logout, name='session_logout'),
    path('send_email_verification_otp/', views.send_email_verification_otp, name='send_email_verification_otp'),
    path('otp_verify/', views.otp_verify, name='otp_verify'),
    path('blog_generator/',views.generate_blog_view,name='blog_generator'),
    path('rephrase-text/',views.rephrasely_view, name='rephrase_text'),
    path('rag_chatbot/',views.chatbot_view,name='rag_chatbot'),
    path('send_feedback/',views.send_feedback,name='send_feedback'),
    path('create_razorpay_order/',views.create_razorpay_order,name='create_razorpay_order'),
    path('verify_payment/',views.verify_payment,name='verify_payment'),
    path('speech_api/',views.speech_api,name='speech_api'),

]

