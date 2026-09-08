import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class CustomUserManager(BaseUserManager):
    """
    Enterprise data manager to handle user provisioning without standard usernames.
    """
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be configured for security logs.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password) # Handles secure PBKDF2 hashing out-of-the-box
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'SECURITY_ADMIN')
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    The core identity schema for SentinelAI operators.
    """
    ROLE_CHOICES = (
        ('SOC_ANALYST', 'SOC Analyst'),
        ('SECURITY_ADMIN', 'Security Administrator'),
    )

    # Cryptographic UUID protects against sequential ID scanning attacks (IDOR prevention)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=255)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='SOC_ANALYST')
    
    # Operational Status flags
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False) # Determines Django admin panel access
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'  # Sets corporate email as the unique login credential
    REQUIRED_FIELDS = []      # Email and Password are required by default

    def __str__(self):
        return f"{self.email} - Scope: [{self.role}]"
    
class SecurityLog(models.Model):
    EVENT_TYPES = [
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('SQL_INJECTION', 'SQL Injection'),
        ('MALWARE_BEACON', 'Malware Beaconing'),
        ('PORT_SCAN', 'Port Scan'),
    ]
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
    ]
    STATUS_CHOICES = [
        ('BLOCKED', 'Blocked'),
        ('ISOLATED', 'Isolated'),
        ('MONITORING', 'Monitoring'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    sourceIp = models.GenericIPAddressField()
    
    # FIXED: Changed max_value to max_length here to satisfy Django core compilation rules
    eventType = models.CharField(max_length=20, choices=EVENT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES)

    def __str__(self):
        return f"{self.eventType} from {self.sourceIp}"