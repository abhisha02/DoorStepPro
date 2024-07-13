from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.shortcuts import render
from .serializers import CustomerSerializer,UserSerializer
from .models import Customer,Otpstore
from django.utils.crypto import get_random_string
from datetime import datetime, timedelta
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed, ParseError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated

# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer =  CustomerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            content = {'Message': 'User Registered Successfully'}
            return Response(content, status=status.HTTP_201_CREATED)
        else:
            errors = serializer.errors
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
        
class RegistrationView(APIView):
    
    def post(self, request):

        if Customer.objects.filter(phone_number=request.data['phone_number']).exists():
            return Response({'error': 'Phone number already exists', 'status': 'error_username'}, status=status.HTTP_400_BAD_REQUEST)
        if Customer.objects.filter(email=request.data['email']).exists():
            return Response({'error': 'Email already exists', 'status': 'error_email'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = CustomerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        first_name = serializer.validated_data.get('first_name')
        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')
       
        
     
        if serializer.is_valid():
            user = serializer.save()

            # otp creation
            otp = get_random_string(length=4, allowed_chars='1234567890')
            expiry = datetime.now() + timedelta(minutes=5)  # OTP expires in 5 minutes
            user_object = get_object_or_404(Customer, email=user.email)
            stored_otp = Otpstore.objects.create(user=user_object, otp = otp)
        
            # otp sending via mail
            subject = 'OTP verification'
            message = f'Hello {first_name},\n\n' \
                        f'Please use the following OTP to verify your email: {otp}\n\n' \
                        f'Thank you!'
            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]
            
            send_mail(subject, message, from_email, recipient_list)
            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

    
class OTPVerificationView(APIView):
    def post(self, request):
        # Extract OTP entered by the user
        entered_otp = request.data.get('otp')
        entered_otp = int(entered_otp)
        first_name = request.data.get('user')

        # Retrieve the stored OTP from the session
        user = Customer.objects.get(first_name=first_name)
        stored_otp = Otpstore.objects.get(user=user)

        if entered_otp == stored_otp.otp:
            # OTP is valid, proceed with user registration
            
            user.is_active = True
            user.is_email_verified=True
            # Save the user
            user.save()
            
            # delete otp from db
            stored_otp.delete()
            return Response({'message': 'Registration successful'}, status=status.HTTP_200_OK)
        else:
            # OTP is invalid
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        


class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        
        try:
            user = Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            user = None
        print(user)
        
        if user is not None and user.check_password(password):
            refresh = RefreshToken.for_user(user)  # Generate refresh token
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'isAdmin':user.is_superuser,
            })
        else:
            return Response({
                'detail': 'Invalid credentials'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(content)
    
class UserDetails(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = Customer.objects.get(id=request.user.id)
        data = UserSerializer(user).data  
        content = data
        return Response(content)
            