from django.contrib import admin
from django.urls import path
from core import views

urlpatterns = [
    path('', views.landing, name='landing'),
    path('about/', views.about, name='about'),
    path('invoice/', views.invoice, name='invoice'),
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
    path('reset_password_with_otp/', views.reset_password_with_otp, name='reset_password_with_otp'),

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
    path('email_generator_guest/',views.email_generator_guest,name='email_generator_guest'),
    path('business_proposal_generator_guest/',views.business_proposal_generator_guest,name='business_proposal_generator_guest'),
    path('offer_letter_generator_guest/',views.offer_letter_generator_guest,name='offer_letter_generator_guest'),
    path('sales_script_generator_guest/',views.sales_script_generator_guest,name='sales_script_generator_guest'),
    path('summarize_document_guest/',views.summarize_document_guest,name='summarize_document_guest'),
    path('content_generator_guest/',views.content_generator_guest,name='content_generator_guest'),
    path('rephrasely_view_guest/',views.rephrasely_view_guest,name='rephrasely_view_guest'),
    path('generate_blog_view_guest/',views.generate_blog_view_guest,name='generate_blog_view_guest'),
    path('translate_content_guest/',views.translate_content_guest,name='translate_content_guest'),
    path('guest_send_otp/',views.guest_send_otp,name='guest_send_otp'),
    path('guest_validate_otp/',views.guest_validate_otp,name='guest_validate_otp'),
    path('profile_info/',views.profile_info,name='profile_info'),
    path('create_cart/', views.create_cart, name='create_cart'), 
    path('get_cart/', views.get_cart, name='get_cart'), 
    path('remove_service/', views.remove_service, name='remove_service'), 
    path('extend_service_yearly/', views.extend_service_yearly, name='extend_service_yearly'), 
    path('create_cart_yearly/', views.create_cart_yearly, name='create_cart_yearly'), 
    path('get_cart_yearly/', views.get_cart_yearly, name='get_cart_yearly'), 
    path('remove_service_yearly/', views.remove_service_yearly, name='remove_service_yearly'), 
    path('empty_cart_yearly/', views.empty_cart_yearly, name='empty_cart_yearly'),  # Add the new path
    path('delete_user_account/', views.delete_user_account, name='delete_user_account'), 
    path('generate_invoice/', views.generate_invoice, name='generate_invoice'), 
    path('invoice-details/', views.invoice_details, name='invoice_details'),  # Add the new path
    path('translate_content_formatted/', views.translate_content_formatted, name='translate_content_formatted'),  # Add the new path
    path('empty_cart/', views.empty_cart, name='empty_cart'),  # Add the new path
    path('translate_json_files_new/',views.translate_json_files_new,name='translate_json_files_new'),
    path('extend_service/',views.extend_service,name='extend_service'),
    path('verify_payment_yearly/',views.verify_payment_yearly,name='verify_payment_yearly'),
    path('translate_and_download_document/',views.translate_and_download_document,name='translate_and_download_document'),
    path('fetch_filtered_payments/', views.fetch_filtered_payments, name='fetch_filtered_payments'),
    path('get_word_count/', views.get_word_count, name='get_word_count'),
    path('translate_content_google/', views.translate_content_google, name='translate_content_google'),
    path('translate_international/', views.translate_international, name='translate_international'),
    path('translate_android/', views.translate_android, name='translate_android'),
    path('email_generator_android/', views.email_generator_android, name='email_generator_android'),
    path('sales_script_generator_android/', views.sales_script_generator_android, name='sales_script_generator_android'),
    path('rephrasely_view_android/', views.rephrasely_view_android, name='rephrasely_view_android'),
    path('generate_blog_view_android/', views.generate_blog_view_android, name='generate_blog_view_android'),
    path('create_presentation_android/', views.create_presentation_android, name='create_presentation_android'),
    path('summarize_document_android/', views.summarize_document_android, name='summarize_document_android'),



    path('signin_android/', views.signin_android, name='signin_android'),
    path('add_user_android/', views.add_user_android, name='add_user_android'),
    path('send_email_verification_otp_android/', views.send_email_verification_otp_android, name='send_email_verification_otp_android'),
    path('otp_verify_android/', views.otp_verify_android, name='otp_verify_android'),
    path('check_session_status_android/', views.check_session_status_android, name='check_session_status_android'),
    path('verify_payment_android/', views.verify_payment_android, name='verify_payment_android'),
    path('content_generator_android/', views.content_generator_android, name='content_generator_android'),

    path('create_razorpay_order_android/', views.create_razorpay_order_android, name='create_razorpay_order_android'),
    path('verify_payment_yearly_android/', views.verify_payment_yearly_android, name='verify_payment_yearly_android'),

    path('logout_view_android/', views.logout_view_android, name='logout_view_android'),
    path('profile_android/', views.profile_android, name='profile_android'),
    path('profile_info_android/', views.profile_info_android, name='profile_info_android'),
    path('speech_api_android/', views.speech_api_android, name='speech_api_android'),




    path('get_user_services_android/<str:email>/', views.get_user_services_android, name='get_user_services_android'),

















]

