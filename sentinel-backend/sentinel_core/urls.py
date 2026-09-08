"""
URL configuration for sentinel_core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
"""
# sentinel_core/urls.py (Your Project's Main URL Configuration)

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # 1. Keeps your login, registration, and token refresh endpoints working perfectly
    path('api/auth/', include('authentication.urls')),
    
    # 2. FIXES THE 404: Directly maps the frontend's security telemetry prefix
    path('api/security/', include('authentication.urls')),
]
