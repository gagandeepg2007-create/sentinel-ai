from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    SentinelTokenObtainView, 
    UserRegistrationView,
    SecurityLogListView,
    LogIngestionUploadView,  
    SecurityDashboardStatsView,
    AutomatedContainmentView
)

urlpatterns = [
    # Core Operator Authentication Gateways
    path('register/', UserRegistrationView.as_view(), name='auth_register'),
    path('login/', SentinelTokenObtainView.as_view(), name='auth_login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='auth_token_refresh'),

    # The Core Unified Log Pipeline Endpoint
    # Root urls.py provides the prefix 'api/security/'
    # Combining this path creates exactly: /api/security/logs/
    path('logs/', SecurityLogListView.as_view(), name='security_logs'),
    
    # Phase 4 Operational Analytics & Dashboard Stats Endpoint
    # Combining this path creates exactly: /api/security/dashboard-stats/
    path('dashboard-stats/', SecurityDashboardStatsView.as_view(), name='dashboard_stats'),

    # Phase 5 Automated Incident Response Endpoint
    path('containment/', AutomatedContainmentView.as_view(), name='automated_containment'),
]