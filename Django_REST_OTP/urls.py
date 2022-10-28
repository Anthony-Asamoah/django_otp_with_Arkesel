from django.contrib import admin
from django.urls import path, include, re_path
from rest_framework import routers

from core import views

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [
	path('', include(router.urls)),
	path('admin/', admin.site.urls),
	re_path(r'^auth/', include('djoser.urls')),
	re_path(r'^auth/', include('djoser.urls.jwt')),

	path('create-otp', views.create_otp, name='create'),
	path('verify-otp', views.verify_otp, name='verify'),
]
