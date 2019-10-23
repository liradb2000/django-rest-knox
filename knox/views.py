from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import DateTimeField
from rest_framework.settings import api_settings
from rest_framework.views import APIView

from knox.auth import TokenAuthentication
from knox.models import AuthToken
from knox.settings import CONSTANTS, knox_settings
from knox.serializers import AuthTokenSerializer 


class LoginView(APIView):
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (IsAuthenticated,)

    def get_context(self):
        return {'request': self.request, 'format': self.format_kwarg, 'view': self}

    def get_token_ttl(self):
        return knox_settings.TOKEN_TTL

    def get_token_limit_per_user(self):
        return knox_settings.TOKEN_LIMIT_PER_USER

    def get_user_serializer_class(self):
        return knox_settings.USER_SERIALIZER

    def get_expiry_datetime_format(self):
        return knox_settings.EXPIRY_DATETIME_FORMAT

    def format_expiry_datetime(self, expiry):
        datetime_format = self.get_expiry_datetime_format()
        return DateTimeField(format=datetime_format).to_representation(expiry)

    def get_post_response_data(self, request, token, instance):
        UserSerializer = self.get_user_serializer_class()

        data = {
            'expiry': self.format_expiry_datetime(instance.expiry),
            'token': token
        }
        if UserSerializer is not None:
            data["user"] = UserSerializer(
                request.user,
                context=self.get_context()
            ).data
        return data

    def post(self, request, format=None):
        queryset = request.user.auth_token_set

        token_limit_per_user = self.get_token_limit_per_user()
        now = timezone.now()

        if request.data.get('will_remove_token') is not None:
            queryset.filter(Q(expiry__lt=now) | Q(token_key__in=request.data.get('will_remove_token'))).delete()
        else:
            queryset.filter(expiry__lt=now).delete()
            

        if token_limit_per_user is not None:
            token = AuthTokenSerializer(queryset.filter(expiry__gt=now), many=True).data

            if len(token) >= token_limit_per_user:
                return Response(
                    {"token": "Maximum amount of tokens allowed per user exceeded.","data":token},
                    status=status.HTTP_403_FORBIDDEN
                )
        token_ttl = self.get_token_ttl()
        instance, token = AuthToken.objects.create(request, token_ttl)
        user_logged_in.send(sender=request.user.__class__,
                            request=request, user=request.user)
                            
        if knox_settings.USE_AUTH_COOKIE:
            response_data = Response(self.get_post_response_data(request, token[:CONSTANTS.TOKEN_KEY_LENGTH], instance))
            response_data.set_cookie(
                knox_settings.AUTH_COOKIE_SETTINGS['NAME'],
                token[CONSTANTS.TOKEN_KEY_LENGTH:],
                expires=instance.expiry,
                path=knox_settings.AUTH_COOKIE_SETTINGS['PATH'],
                domain=knox_settings.AUTH_COOKIE_SETTINGS['DOMAIN'],
                secure=knox_settings.AUTH_COOKIE_SETTINGS['SECURE'],
                httponly=knox_settings.AUTH_COOKIE_SETTINGS['HTTP_ONLY'],
                samesite=knox_settings.AUTH_COOKIE_SETTINGS['SAMESITE']
            )
            return response_data

        return Response(self.get_post_response_data(request, token, instance))


class LogoutView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        request._auth.delete()
        user_logged_out.send(sender=request.user.__class__,
                             request=request, user=request.user)
        return Response(None, status=status.HTTP_204_NO_CONTENT)


class LogoutAllView(APIView):
    '''
    Log the user out of all sessions
    I.E. deletes all auth tokens for the user
    '''
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        request.user.auth_token_set.all().delete()
        user_logged_out.send(sender=request.user.__class__,
                             request=request, user=request.user)
        return Response(None, status=status.HTTP_204_NO_CONTENT)
