from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import (
    UserSerializer,
    UserProfileSerializer,
    EmailSerializer,
    ChangePasswordRequestSerializer,
    UserProfileUpdateSerializer,
    FamilyInfoSerializer,
    MemberDetailSerializer,
    GetFamilyInfoSerializer
)
from .models import User, UserToken
from rest_framework import status
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
import random
import string
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.tokens import AccessToken
from .models import FamilyInfo, MemberDetail
import jsonschema
import json
from .utils import send_email_to_admin, chat_with_gpt, generate_dynamic_schema, encrypt, decrypt, generate_prompt 
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import get_object_or_404
from django.db import transaction
  

class UserRegistrationView(APIView):
    def post(self, request):
        """
        Handle user registration.
        """
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            response_data = {
                "message": "User registered successfully",
                "user": {
                    "fullName": user.name,
                    "email": user.email,
                    "password": user.password,
                    "isPaid": user.isPaid,
                    "TrialsLeft": user.TrialsLeft,
                    "createdAt": user.createdAt,
                    "updatedAt": user.updatedAt,
                },
                "id": str(user.id),
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        """
        Handle user login.
        """
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)

            refresh_token = refresh
            access_token = refresh.access_token

            serializer = UserProfileSerializer(user)

            response_data = {
                "user": serializer.data,
                "status": status.HTTP_200_OK,
                "message": "Success",
                "access_token": str(access_token),
            }

            return Response(response_data, status=status.HTTP_200_OK)

        return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        """
        Get user profile.
        """
        user = request.user
        if user:
            user_id_from_token = user.id
            # user_id_from_request = request.data.get('user_id')

            if user_id is None:
                return Response({"message": "User Id is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)

            if user_id_from_token is None:
                return Response({"message": "Token is missing or invalid"}, status=status.HTTP_401_UNAUTHORIZED)

            if user_id_from_token != user_id:
                return Response({"message": "Access denied"}, status=status.HTTP_403_FORBIDDEN)

            serializer = UserProfileSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class forgot_password_email(APIView):
    def post(self, request):
        """
        Handle forgot password email request.
        """
        email_serializer = EmailSerializer(data=request.data)
        if email_serializer.is_valid():
            email_data = email_serializer.validated_data
            user = User.objects.filter(email=email_data['email']).first()

            if user:
                token = self.generate_short_token(20)
                UserToken.objects.update_or_create(user=user, defaults={'token': token})

                reset_link = f"http://tummytango.com/reset-password?token={token}"

                subject = 'Forgot Password Request'
                message = f"Dear {user.name},\n\n"
                message += "A forgot-password request has been received from this email id from TummyTango.\n\n"
                message += f"Click the following link to reset your password {reset_link}\n\n"
                message += "Thank You,\nTummyTango"
                sender_email = settings.SENDER_EMAIL
                reciever_email = [email_data['email']]

                send_mail(
                    subject,
                    message,
                    sender_email,
                    reciever_email,
                    fail_silently=False,
                )

                return Response({"message": "Email has been sent"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(email_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def generate_short_token(self, length):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))


class ChangePasswordReset(APIView):
    def post(self, request):
        """
        Handle change password request.
        """
        serializer = ChangePasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            token = request.data.get("token")
            new_password = request.data.get("newPassword")
            confirm_password = request.data.get("confirmPassword")

            if new_password != confirm_password:
                return Response({"detail": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

            user_token = UserToken.objects.filter(token=token).first()

            if user_token:
                user = User.objects.filter(email=user_token.user).first()

                if user:
                    user.set_password(new_password)
                    user.save()
                    return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
                else:
                    return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({"detail": "Token not found or expired"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 

class UserProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        """
        Handle user profile update.
        """
        user = request.user
        print("user", user)
        print("user", user.id)


        # Check if the user has permission to update the profile
        if user.id != int(user_id):
            return Response({"message": "Access denied"}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserProfileUpdateSerializer(data=request.data)
        if serializer.is_valid():
            # user = request.user
            data = serializer.validated_data

            if data.get('full_name'):
                user.name = data['full_name']

            if data.get('email'):
                new_email = data['email']
                if User.objects.filter(email=new_email).exclude(id=user.id).exists():
                    return Response({'email': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
                user.email = new_email

            if data.get('password'):
                password = data['password']
                confirm_password = data.get('confirm_password')

                if password != confirm_password:
                    return Response({'confirm_password': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

                user.set_password(password)

            user.save()

            response_data = {
                "message": "User profile updated successfully",
                "user": {
                    "full_name": user.name,
                    "email": user.email,
                }
            }

            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CreateGeneratePlan(APIView):
    """
    Handle Create Generate plans for User as per the trial left.
    """
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
            # Extract family info data from the request
            family_info_data = request.data
            try:
                # Get user data based on the 'userId' from the family info data
                user_data = User.objects.get(id=family_info_data['userId'])
                trials_left = user_data.TrialsLeft

                if trials_left > 0:
                    # Retrieve family data information
                    family_data_information = self.getFamilyData(family_info_data)
                    print("family_data_information====>>>>" , family_data_information)

                    response_list = []
                    num_response = 2

                    for i in range(num_response):
                        # Call the chat_with_gpt function with family data and get a response
                        response = chat_with_gpt(family_data_information)
                        print("response ====    >>>>, " , i,  response)
 
                        try:
                            # Try to parse the response as JSON
                            resp_data = json.loads(response)
                            if isinstance(resp_data, list):
                                response_list.append(response)
                                break

                        except json.JSONDecodeError:
                            if i == 1:
                                # To send an email to admin
                                send_email_to_admin(response)
                                return Response({"message": "OOPS! We are encountering some issue, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                    if response_list:
                        for response_json in response_list:
                            try:
                                response2 = [json.loads(response_json) for response_json in response_list]

                                if isinstance(response2, list):
                                    # Decrease the user's trials left count and save the user data
                                    user_data = User.objects.get(id=family_info_data['userId'])
                                    user_data.TrialsLeft -= 1
                                    user_data.save()
                                    user_serializer = UserSerializer(user_data)

                                    return Response({
                                        "message": "Success",
                                        "data": response_json,
                                        "updateData": user_serializer.data
                                    }, status=status.HTTP_200_OK)

                            except json.JSONDecodeError:
                                # To send an email to admin
                                send_email_to_admin(response_json)
                                return Response({"message": "OOPS! We are encountering some issue, please try again.1."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                                    

                        return Response({"message": "OOPS! We are encountering some issue, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else:
                        # To send an email to admin
                        send_email_to_admin(response)
                        return Response({"message": "OOPS! We are encountering some issue, please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response({"message": "You haven't trials left."})
            except ObjectDoesNotExist:
                # Return a response if the user is not found
                return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)


    def getFamilyData(self, family_info_data):
        # Extract members data from the request data
        members_data = family_info_data.pop("members")

        # Check if a FamilyInfo instance exists for the provided userId
        user_id = family_info_data.get("userId")
        try:
            family_info = FamilyInfo.objects.get(userId=user_id)

            if family_info:
                family_info_serializer = FamilyInfoSerializer(instance=family_info, data=family_info_data)

            else:
                family_info_serializer = FamilyInfoSerializer(data=family_info_data)

            if family_info_serializer.is_valid():
                family_info = family_info_serializer.save()
                family_meal_str = ', '.join(family_info.meal)

                # Generate a dynamic schema based on the selected meals
                dynamic_schema = generate_dynamic_schema(family_info.meal)
                dynamic_schema_json = json.dumps(dynamic_schema)

                for member_data in members_data:
                    family_info_id = family_info.id if family_info else None
                    member_data["familyInfoId"] = family_info_id

                    # Check if a MemberDetail instance exists for the provided familyInfoId
                    family_info_id = member_data.get("familyInfoId")
                    existing_member_details = MemberDetail.objects.filter(familyInfoId=family_info_id)


                    with transaction.atomic():
                        # Use a database transaction to ensure atomicity
                        if existing_member_details.exists():
                            # Delete all existing MemberDetail instances with the same familyInfoId
                            existing_member_details.delete()
                                
                        
                member_detail = []
                for member_data in members_data:
                    family_info_id = family_info.id if family_info else None
                    member_data["familyInfoId"] = family_info_id

                    # Extract allergy and medical condition information for family members
                    allergy1 = member_data["allergy"]
                    medical_condition1 = member_data["medicalCondition"]

                    # Encrypt allergy and medical condition data
                    allergy = encrypt(allergy1) if allergy1 else None

                    medical_condition = encrypt(medical_condition1) if medical_condition1 else None

                    # Convert encrypted data to strings
                    allergy = allergy.decode() if allergy else None
                    medical_condition = medical_condition.decode() if medical_condition else None

                    # Set the encrypted values in the member_data dictionary
                    member_data["allergy"] = allergy
                    member_data["medicalCondition"] = medical_condition

                    # Associate the member's data with the family info
                    member_data["familyInfoId"] = family_info.id
                    member_serializer = MemberDetailSerializer(data=member_data)

                    member_detail.append(f'1 person is allergic to {allergy1} and has a medical history of {medical_condition1}.')
                    if member_serializer.is_valid():
                        member_serializer.save()
                    else:
                        print("Validation errors:", member_serializer.errors)

            # Create a prompt for generating a meal plan                        
            prompt = generate_prompt(family_info, dynamic_schema_json, family_meal_str, member_detail)
            
            return prompt 

        except FamilyInfo.DoesNotExist:    
            # Create FamilyInfo instance
            family_info_serializer = FamilyInfoSerializer(data=family_info_data)

            if family_info_serializer.is_valid():
                family_info = family_info_serializer.save()

                family_meal_str = ', '.join(family_info.meal)

                # Generate a dynamic schema based on the selected meals
                dynamic_schema = generate_dynamic_schema(family_info.meal)
                dynamic_schema_json = json.dumps(dynamic_schema)

                member_detail = []
                for member_data in members_data:
                    # Extract allergy and medical condition information for family members
                    allergy1 = member_data["allergy"]
                    medical_condition1 = member_data["medicalCondition"]

                    # Encrypt allergy and medical condition data
                    allergy = encrypt(allergy1) if allergy1 else None

                    medical_condition = encrypt(medical_condition1) if medical_condition1 else None

                    # Convert encrypted data to strings
                    allergy = allergy.decode() if allergy else None
                    medical_condition = medical_condition.decode() if medical_condition else None

                    # Set the encrypted values in the member_data dictionary
                    member_data["allergy"] = allergy
                    member_data["medicalCondition"] = medical_condition

                    # Associate the member's data with the family info
                    member_data["familyInfoId"] = family_info.id
                    member_serializer = MemberDetailSerializer(data=member_data)

                    member_detail.append(f'1 person is allergic to {allergy1} and has a medical history of {medical_condition1}.')

                    if member_serializer.is_valid():
                        # Save the valid member data
                        member_serializer.save()

                    else:
                        print("Validation errors:", member_serializer.errors)
                        print("data not saved")

            # Create a prompt for generating a meal plan
            prompt = generate_prompt(family_info, dynamic_schema_json, family_meal_str, member_detail)  

            return prompt   
            

class FamilyMemberDetailByUserId(APIView):    
    """
    Handle Get Family and member data .
    """
    permission_classes = [IsAuthenticated]
    def get(self, request, user_id):
        try:
            family_info = FamilyInfo.objects.get(userId=user_id)
            serializer = GetFamilyInfoSerializer(family_info)

            # Decrypt allergy and medicalCondition for each member
            for member in serializer.data['members']:
                member['allergy'] = decrypt(member['allergy'])
                member['medicalCondition'] = decrypt(member['medicalCondition'])

            return Response(serializer.data)
        except FamilyInfo.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"message": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
           
















