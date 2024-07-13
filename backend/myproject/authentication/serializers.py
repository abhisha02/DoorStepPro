from rest_framework_simplejwt.serializers import TokenObtainPairSerializer,TokenRefreshSerializer
from rest_framework import serializers
from .models import Customer,Otpstore
from rest_framework_simplejwt.tokens import RefreshToken, Token,AccessToken
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError as DjangoValidationError



class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['first_name'] = Customer.first_name
        # ...
        
        return token
    


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['email', 'phone_number', 'first_name', 'last_name', 'password']  # Include 'password' if you want to accept it during registration
        extra_kwargs = {
            'password': {'write_only': True},  # Ensures password is write-only
        }

    def create(self, validated_data):
        user = Customer.objects.create_user(**validated_data)
        return user
    
# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        exclude = ('password',)
