from django.contrib.auth.models import AbstractUser, BaseUserManager, Group, Permission
from django.db import models
from django.utils.translation import gettext as _

class CustomerManager(BaseUserManager):
    def create_user(self, email, phone_number, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, phone_number, password, **extra_fields)

class Customer(AbstractUser):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50, blank=True)
    phone_number = models.CharField(max_length=12, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    is_email_verified = models.BooleanField(default=False)
    profile = models.ImageField(upload_to='user_profiles', blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    is_staff=models.BooleanField(default=False)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone_number', 'first_name', 'last_name']

    objects = CustomerManager()

    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        related_name="customuser_groups",
        related_query_name="customuser",
        help_text=_(
            'The groups this customer belongs to. A customer will get all permissions '
            'granted to each of their groups.'
        ),
    )

    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        related_name="customuser_user_permissions",
        related_query_name="customuser",
        help_text=_('Specific permissions for this user.'),
    )

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
    
class Otpstore(models.Model):
    user = models.OneToOneField(Customer, on_delete=models.CASCADE)
    otp = models.IntegerField()
