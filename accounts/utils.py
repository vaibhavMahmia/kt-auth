from django.core.mail import EmailMessage
import os


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email='nup.try28@gmail.com',
            to=[data['to_email']]
        )
        email.send()