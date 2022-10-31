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
from .otp import TOTPVerification
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

	# send otp via sms using Arkesel
	response = httpx.post(
		url=f'https://sms.arkesel.com/api/v2/sms/send/',
		headers={'API-KEY': os.getenv('ARKESEL_API_KEY')},
		json={
			"sandbox": True,
			"sender": "MyHealthCop",
			"message": f"Your one time passcode is {token}",
			"recipients": [device.main_contact, ]
		})
	logging.info(response.json())
	sms_is_sent = response.is_success

	# save token info to instance
	device.otp = md5Token.hexdigest()
	device.otp_isValid = True
	device.otp_timestamp = time.time()
	device.save()

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


def get_otp(request):  # using TOTPVerification
	jwt_object = JWTAuthentication()

	header = jwt_object.get_header(request)
	raw_token = jwt_object.get_raw_token(header)
	validated_token = jwt_object.get_validated_token(raw_token)
	user = jwt_object.get_user(validated_token)

	# create token
	otp = TOTPVerification()
	token, key = otp.generate_token()

	# get user instance
	device = Ext_user.objects.get(user=user.id)
	logging.info(device)

	# save token info to instance
	device.otp = token
	device.otp_stamp = key
	# device.otp_isValid = True
	try:
		device.save()
	except Exception as e:
		logging.warning(f'Error while saving token: {e}')
	return JsonResponse(
		{
			'message': 'Index Works',
			'status': 'SUCCESS',
			'detail': [{
				'otp': token,
				'stamp': key
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
		logging.info(device)

		isVerified = False
		if device.otp_isValid and time.time() - device.otp_timestamp < int(os.getenv("VALID_OTP_DURATION")):
			isVerified: bool = (hashlib.md5(code.encode()).hexdigest() == device.otp)
			if isVerified:
				device.otp_isValid = False
				device.save()

		return JsonResponse(
			{
				'message': 'Index Works',
				'status': 'SUCCESS',
				'detail': [{
					'valid': f'{isVerified}'
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
