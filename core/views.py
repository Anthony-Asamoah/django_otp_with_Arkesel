import hashlib
import logging
import os
import time

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

	# save token info to instance
	device.otp = md5Token.hexdigest()
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
		# key = request.POST['key']

		# get user instance
		device = Ext_user.objects.get(user=user.id)
		logging.info(device)

		# verify token
		# device = TOTPVerification(key=key)
		# isVerified = device.verify_token(code)

		isVerified = (hashlib.md5(code.encode()).hexdigest() == device.otp)

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


# ###################################### Django_otp_abstracted method #########################################
#
# def create_user(request):
# 	jwt_object = JWTAuthentication()
#
# 	header = jwt_object.get_header(request)
# 	raw_token = jwt_object.get_raw_token(header)
# 	validated_token = jwt_object.get_validated_token(raw_token)
# 	user = jwt_object.get_user(validated_token)
#
# 	device = ArkeselSMSDevice(user=user, number="233503032976")
# 	hasDevice = django_otp.user_has_device(user=user)
#
# 	return JsonResponse(
# 		{
# 			'message': 'Index Works',
# 			'status': 'SUCCESS',
# 			'detail': [{
# 				'check': hasDevice if hasDevice else ArkeselSMSDevice.generate_challenge(device),
# 				'interactive': device.is_interactive(),
# 				'id': device.persistent_id
# 			}]
# 		}
# 	)
#
#
# def get_otp(request):
# 	jwt_object = JWTAuthentication()
#
# 	header = jwt_object.get_header(request)
# 	raw_token = jwt_object.get_raw_token(header)
# 	validated_token = jwt_object.get_validated_token(raw_token)
# 	user = jwt_object.get_user(validated_token)
#
# 	device = ArkeselSMSDevice(user=user, number="233503032976")
#
# 	return JsonResponse(
# 		{
# 			'message': 'Index Works',
# 			'status': 'SUCCESS',
# 			'detail': [{
# 				# 'check': SideChannelDevice.generate_token(length=6, valid_secs=300, commit=True, self=device),
# 				'check': device.generate_challenge()
# 			}]
# 		}
# 	)
#
#
# @csrf_exempt
# def verify_otp(request):
# 	jwt_object = JWTAuthentication()
#
# 	header = jwt_object.get_header(request)
# 	raw_token = jwt_object.get_raw_token(header)
# 	validated_token = jwt_object.get_validated_token(raw_token)
# 	user = jwt_object.get_user(validated_token)
#
# 	if request.method == 'POST':
# 		code = request.POST['otp']
#
# 		# device = Device(user=user)
# 		# isValid = Device.verify_token(device, code)
# 		matched = django_otp.match_token(token=code, user=user)
#
# 		with atomic():
#
# 			return JsonResponse(
# 				{
# 					'message': 'Index Works',
# 					'status': 'SUCCESS',
# 					'detail': [{
# 						'valid': 'False' if matched is None else str(matched.verify_token(code))
# 					}]
# 				}
# 			)
# 	else:
# 		raise BadRequest("Invalid Method 'GET'")
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
