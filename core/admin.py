from django.contrib import admin
from django.contrib.admin.sites import AlreadyRegistered

from . import models
from .models import ArkeselSMSDevice


# Register your models here.


@admin.register(models.User)
class UserAdmin(admin.ModelAdmin):
	list_display = ['user', 'main_contact']
	readonly_fields = ['otp', 'otp_stamp']
	list_display_links = list_display


class ArkeselSMSDeviceAdmin(admin.ModelAdmin):
	"""
	:class:`~django.contrib.admin.ModelAdmin` for
	:class:`~otp_Arkesel.models.ArkeselSMSDevice`.
	"""
	fieldsets = [
		('Identity', {
			'fields': ['user', 'name', 'confirmed'],
		}),
		('Configuration', {
			'fields': ['number'],
		}),
	]
	raw_id_fields = ['user']


try:
	admin.site.register(ArkeselSMSDevice, ArkeselSMSDeviceAdmin)
except AlreadyRegistered:
	# Ignore the useless exception from multiple imports
	pass
