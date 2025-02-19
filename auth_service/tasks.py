from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings


@shared_task
def send_otp_email(email, otp):
    try:
        """Send OTP Email"""
        subject = 'Your OTP Code'
        message = f'Your OTP code is {otp}. It is valid for 5 minutes.'
        html_message = f'''
        <html>
            <body>
                <h1>Your OTP Code</h1>
                <p>Your OTP code is <strong>{otp}</strong>. It is valid for 5 minutes.</p>
            </body>
        </html>
        '''
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, email_from, recipient_list, html_message=html_message)
    except Exception as e:
        print("Exception while sending mail", e)
        return False
    

@shared_task
def send_password_reset_link_mail(email, reset_link):
    try:
        """Send Password Reset Email"""
        subject = 'Password Reset Request'
        message = f'Click the link to reset your password: {reset_link}'
        html_message = f'''
        <html>
            <body>
                <h1>Password Reset Request</h1>
                <p>Click the link below to reset your password:</p>
                <p><a href="{reset_link}">{reset_link}</a></p>
            </body>
        </html>
        '''
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, email_from, recipient_list, html_message=html_message)
    except Exception as e:
        print("Exception while sending mail", e)
        return False
