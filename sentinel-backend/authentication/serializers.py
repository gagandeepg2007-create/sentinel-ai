from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from .models import SecurityLog

User = get_user_model()

class SentinelTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT builder that embeds security access roles directly into the token payload claims.
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Inject identity tracking metadata fields into the stateless token payload
        token['email'] = user.email
        token['role'] = user.role
        
        return token

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Validates and provisions incoming operator account credentials.
    """
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('email', 'password', 'role')

    def create(self, validated_data):
        # Utilizes our manager logic to hash the incoming raw string password cleanly
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data.get('role', 'SOC_ANALYST')
        )
        return user

class SecurityLogSerializer(serializers.ModelSerializer):
    """
    Formats the system database telemetry logs to match the TypeScript interface exactly.
    """
    # Formats the database datetime to match your frontend expectation string explicitly
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    
    class Meta:
        model = SecurityLog
        fields = ['id', 'timestamp', 'sourceIp', 'eventType', 'severity', 'status']