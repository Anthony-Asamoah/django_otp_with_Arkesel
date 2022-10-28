import os

import django.conf
import django.test.utils


class Settings(object):
	"""
	This is a simple class to take the place of the global settings object. An
	instance will contain all of our settings as attributes, with default
	values if they are not specified by the configuration.
	"""
	_defaults = {
		'OTP_ARKESEL_TOKEN_TEMPLATE': '{token}',

		'ARKESEL_API_KEY': os.getenv("ARKESEL_API_KEY"),
		'OTP_ARKESEL_FROM': "MyHealthCOP",
		'OTP_ARKESEL_CHALLENGE_MESSAGE': "SMS sent",
		'OTP_ARKESEL_THROTTLE_FACTOR': 1,

		'OTP_ARKESEL_SANDBOX': True,
		'OTP_ARKESEL_NO_DELIVERY': False,

		'OTP_LENGTH': int(os.getenv('OTP_LENGTH')),
		'OTP_ARKESEL_TOKEN_VALIDITY': int(os.getenv('VALID_OTP_DURATION'))
	}

	def __getattr__(self, name):
		if hasattr(django.conf.settings, name):
			value = getattr(django.conf.settings, name)
		elif name in self._defaults:
			value = self._defaults[name]
		else:
			raise AttributeError(name)

		return value


settings = Settings()
