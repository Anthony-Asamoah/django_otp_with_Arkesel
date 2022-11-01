from django.contrib.auth.models import User, Group
from django.core.exceptions import BadRequest
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import permissions
from rest_framework import viewsets

from .models import ArkeselSMSDevice
from .serializers import UserSerializer


# Create your views here.


def create_otp(request):
    # jwt_object = JWTAuthentication()

    # header = jwt_object.get_header(request)
    # raw_token = jwt_object.get_raw_token(header)
    # validated_token = jwt_object.get_validated_token(raw_token)
    # user = jwt_object.get_user(validated_token)

    # create device instance
    # device = ArkeselSMSDevice(user=User.objects.all()[0], number="233503032976")

    user = User.objects.first()
    try:
        device = user.arkeselsmsdevice_set.create(number='+233269192964')
    except Exception as e:
        device = ArkeselSMSDevice.objects.get(number='+233269192964')

    # generate token and send sms
    token = device.generate_challenge()

    # get otp code from sms and verify directly in this function
    # note otp can only be verified once. it is rendered invalid afterwards.
    # otp = sms_status.split(' ')[-1]
    # isVerified = device.verify_token(otp)

    return JsonResponse(
        {
            'message': 'Token delivered',
            'status': 'success',
            'detail': [{
                'token': token
            }]
        }
    )


@csrf_exempt
def verify_otp(request):
    # jwt_object = JWTAuthentication()
    #
    # header = jwt_object.get_header(request)
    # raw_token = jwt_object.get_raw_token(header)
    # validated_token = jwt_object.get_validated_token(raw_token)
    # user = jwt_object.get_user(validated_token)

    if request.method == 'POST':
        code = request.POST['otp']
        device = ArkeselSMSDevice.objects.get(number='+233269192964')
        is_verified = device.verify_token(code)

        return JsonResponse(
            {
                'message': 'Token Verification Status',
                'status': 'success',
                'detail': [{
                    'token_verified': is_verified
                }]
            }
        )

    # device = Device(user=user)
    # isValid = Device.verify_token(device, code)
    # matched = django_otp.match_token(token=code, user=User.objects.all()[0])

    # with atomic():
    #
    # 	return JsonResponse(
    # 		{
    # 			'message': 'Index Works',
    # 			'status': 'SUCCESS',
    # 			'detail': [{
    # 				'valid': 'False' if matched is None else str(matched.verify_token(code))
    # 			}]
    # 		}
    # 	)
    else:
        raise BadRequest("Invalid Method 'GET'")


##################################################################################################

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
