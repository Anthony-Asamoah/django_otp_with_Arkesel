import logging

import httpx
from django.contrib.auth.models import User as AuthUser
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.encoding import force_str
from django_otp.models import SideChannelDevice, ThrottlingMixin
from django_otp.util import hex_validator, random_hex

from .conf import settings


# Create your models here.


class User(models.Model):  # extended user model
	user = models.OneToOneField(AuthUser, on_delete=models.CASCADE, blank=True, null=True)
	main_contact = models.CharField(max_length=12, null=True, blank=True)
	otp = models.CharField(max_length=4, null=True, blank=True)
	# otp_isValid = models.BooleanField(default=False)
	otp_stamp = models.CharField(max_length=50, blank=True, null=True)

	def __str__(self):
		return f'User #{self.id}'


def default_key():  # pragma: no cover
	""" Obsolete code here for migrations. """
	return force_str(random_hex(20))


def key_validator(value):  # pragma: no cover
	""" Obsolete code here for migrations. """
	return hex_validator(20)(value)


class ArkeselSMSDevice(ThrottlingMixin, SideChannelDevice):
	"""
	A :class:`~django_otp.models.SideChannelDevice` that delivers a token via
	the Arkesel SMS service.
	The tokens are valid for :setting:`OTP_ARKESEL_TOKEN_VALIDITY` seconds.
	"""
	number = models.CharField(
		max_length=30,
		help_text="The mobile number to deliver tokens to."
	)

	class Meta(SideChannelDevice.Meta):
		verbose_name = "Arkesel SMS Device"

	def get_throttle_factor(self):
		return settings.OTP_ARKESEL_THROTTLE_FACTOR

	def generate_challenge(self):
		"""
		Sends the current TOTP token to ``self.number``.
		:returns: :setting:`OTP_ARKESEL_CHALLENGE_MESSAGE` on success.
		:raises: Exception if delivery fails.
		"""
		self.generate_token(valid_secs=settings.OTP_ARKESEL_TOKEN_VALIDITY, length=settings.OTP_LENGTH)

		message = settings.OTP_ARKESEL_TOKEN_TEMPLATE.format(token=self.token)

		if settings.OTP_ARKESEL_NO_DELIVERY:
			logging.info(message)
			logging.info(f'''Format: {
			"sender": settings.OTP_ARKESEL_FROM,
							"message": "just another test, token: {message}",
							"recipients": [str(self.number), ]
						}''')
		else:
			self._deliver_token(message)

		challenge = settings.OTP_ARKESEL_CHALLENGE_MESSAGE.format(token=self.token)

		return challenge

	def _deliver_token(self, token):
		self._validate_config()

		url = f'https://sms.arkesel.com/api/v2/sms/send/'
		payload = {
			"sender": settings.OTP_ARKESEL_FROM,
			"message": f"just another test, token: {token}",
			"recipients": [str(self.number), ]
		}
		if settings.OTP_ARKESEL_SANDBOX:
			payload['sandbox'] = True

		response = httpx.post(url, json=payload, headers={'API-KEY': settings.ARKESEL_API_KEY}, timeout=None)
		logging.info(f'Response: {response.json()}\n')
		logging.debug(f'Message: {payload}\n')
		try:
			response.raise_for_status()
		except Exception as e:
			logging.exception(f'Error sending otp by Arkesel SMS: {e}')
			raise

		if response.is_error:
			message = response.json().get('message')
			logging.error(f'Error sending token by Arkesel SMS: {message}')
			raise Exception(message)

	def _validate_config(self):
		if settings.ARKESEL_API_KEY is None:
			raise ImproperlyConfigured('ARKESEL_API_KEY must be set to your Arkesel API key')

		if settings.OTP_ARKESEL_FROM is None:
			raise ImproperlyConfigured('OTP_ARKESEL_FROM requires a sender name')

	def verify_token(self, token):
		verify_allowed, _ = self.verify_is_allowed()
		if verify_allowed:
			verified = super().verify_token(token)

			if verified:
				self.throttle_reset()
			else:
				self.throttle_increment()
		else:
			verified = False

		return verified
