from django.contrib.auth import get_user_model
from rest_framework import serializers
from knox.models import AuthToken
User = get_user_model()

username_field = User.USERNAME_FIELD if hasattr(User, 'USERNAME_FIELD') else 'username'


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (username_field,)

class AuthTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthToken
        fields = ('created', 'browser', 'device', 'token_key')