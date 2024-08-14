# import logging
# from django.utils.deprecation import MiddlewareMixin
# from django.contrib.auth.signals import user_logged_in, user_logged_out
# from django.dispatch import receiver
# from datetime import datetime

# audit_logger = logging.getLogger('audit')

# class APILoggingMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         method = request.method
#         path = request.path
#         user = request.user if request.user.is_authenticated else 'Anonymous'
        
#         try:
#             data = request.body.decode('utf-8') if request.body else 'No body'
#         except UnicodeDecodeError:
#             data = 'Binary data (not logged)'

#         audit_logger.info(f"API call: Method={method}, Path={path}, User={user}, Data={data}")

#     def process_response(self, request, response):
#         response_status = response.status_code
#         audit_logger.info(f"API response: Status={response_status}, Path={request.path}")
#         return response

# @receiver(user_logged_in)
# def log_user_login(sender, request, user, **kwargs):
#     current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#     audit_logger.info(f"User logged in: User={user.username}, Time={current_time}")

# @receiver(user_logged_out)
# def log_user_logout(sender, request, user, **kwargs):
#     current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#     audit_logger.info(f"User logged out: User={user.username}, Time={current_time}")
