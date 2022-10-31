import hashlib
import logging
import os
import time

import httpx
from django.contrib.auth.models import User, Group
from django.core.exceptions import BadRequest
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_otp.oath import TOTP
from django_otp.util import random_hex
from rest_framework import permissions
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication

from core.models import User as Ext_user
from .serializers import UserSerializer


# Create your views here.


def create_user(request):  # using manual method
	jwt_object = JWTAuthentication()

	header = jwt_object.get_header(request)
	raw_token = jwt_object.get_raw_token(header)
	validated_token = jwt_object.get_validated_token(raw_token)
	user = jwt_object.get_user(validated_token)

	# create token
	totp = TOTP(
		key=random_hex(20).encode(),
		step=int(os.getenv('VALID_OTP_DURATION')),
		digits=int(os.getenv('OTP_LENGTH'))
	)
	totp.time = time.time()
	token = str(totp.token()).zfill(4)
	md5Token = hashlib.md5(token.encode())

	# get user instance
	device = Ext_user.objects.get(user=user.id)
	logging.info(device)

	# save token info to instance
	device.otp = md5Token.hexdigest()
	device.otp_isValid = True
	device.otp_timestamp = time.time()
	device.save()

	# send otp via sms using Arkesel
	try:
		response = httpx.post(
			url=f'https://sms.arkesel.com/api/v2/sms/send/',
			headers={'API-KEY': os.getenv('ARKESEL_API_KEY')},
			json={
				"sandbox": True,
				"sender": "MyHealthCop",
				"message": f"Your one time passcode is {token}",
				"recipients": [device.main_contact, ],
			},
			timeout=None
		)
		logging.info(response.json())
		sms_is_sent = response.is_success
	except ConnectionError as ce:
		logging.info(ce)
		sms_is_sent = False

	return JsonResponse(
		{
			'message': 'Index Works',
			'status': 'SUCCESS',
			'detail': [{
				'otp': token,
				'SMS Sent': sms_is_sent,
			}]
		}
	)


@csrf_exempt
def verify_otp(request):
	jwt_object = JWTAuthentication()

	header = jwt_object.get_header(request)
	raw_token = jwt_object.get_raw_token(header)
	validated_token = jwt_object.get_validated_token(raw_token)
	user = jwt_object.get_user(validated_token)

	if request.method == 'POST':
		code = request.POST['otp']

		# get user instance
		device = Ext_user.objects.get(user=user.id)
		token_is_expired = round(time.time() - device.otp_timestamp) > int(os.getenv("VALID_OTP_DURATION"))
		logging.info(device)

		isVerified = False
		if token_is_expired:
			device.otp_isValid = False
		elif device.otp_isValid and not token_is_expired:
			isVerified: bool = (hashlib.md5(code.encode()).hexdigest() == device.otp)
		if isVerified:
			device.otp_isValid = False
			device.user_is_phone_verified = True
		device.save()

		return JsonResponse(
			{
				'message': 'Index Works',
				'status': 'SUCCESS',
				'detail': [{
					'valid': f'{isVerified}',
					'expired': token_is_expired,
					'expiry': os.getenv("VALID_OTP_DURATION"),
				}]
			}
		)
	else:
		raise BadRequest("Invalid Method 'GET'")


###################################################################################################

class UserViewSet(viewsets.ModelViewSet):
	"""
	API endpoint that allows users to be viewed or edited.
	"""
	queryset = User.objects.all().order_by('-date_joined')
	serializer_class = UserSerializer
	permission_classes = [permissions.IsAuthenticated]


class GroupSerializer:
	pass


class GroupViewSet(viewsets.ModelViewSet):
	"""
	API endpoint that allows groups to be viewed or edited.
	"""
	queryset = Group.objects.all()
	serializer_class = GroupSerializer
	permission_classes = [permissions.IsAuthenticated]
