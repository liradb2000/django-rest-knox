from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework import status

from knox.models import AuthToken
from knox.settings import CONSTANTS, knox_settings
from knox.serializers import AuthTokenSerializer 

class KnoxLoginMixin():
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

    def modify_response(self, response, instance):
        if knox_settings.USE_COOKIE:
            response.set_cookie(
                knox_settings.COOKIE_SETTINGS['NAME'],
                instance.token[CONSTANTS.TOKEN_KEY_LENGTH:],
                expires=instance.expiry,
                path=knox_settings.COOKIE_SETTINGS['PATH'],
                domain=knox_settings.COOKIE_SETTINGS['DOMAIN'],
                secure=knox_settings.COOKIE_SETTINGS['SECURE'],
                httponly=knox_settings.COOKIE_SETTINGS['HTTP_ONLY'],
                samesite=knox_settings.COOKIE_SETTINGS['SAMESITE']
            )
        return response

    def create_token(self, user):
        request = self.request
        if request.user.is_anonymous and user is not None: 
            request.user=user

        # TODO: Create Multiple token (like: token per login)
        # queryset=request.user.auth_token_set

        # token_limit_per_user = self.get_token_limit_per_user()
        # now = timezone.now()

        # if request.data.get('will_remove_token') is not None:
        #     queryset.filter(Q(expiry__lt=now) | Q(token_key__in=request.data.get('will_remove_token'))).delete()
        # else:
        #     queryset.filter(expiry__lt=now).delete()
            

        # if token_limit_per_user is not None:
        #     token = AuthTokenSerializer(queryset.filter(expiry__gt=now), many=True).data

        #     if len(token) >= token_limit_per_user:
        #         raise Response(
        #             {"token": "Maximum amount of tokens allowed per user exceeded.","data":token},
        #             status=status.HTTP_403_FORBIDDEN
        #         )
        
        token_ttl = self.get_token_ttl()
        instance, iscreate = AuthToken.objects.update_or_create(request.user, token_ttl)
        user_logged_in.send(sender=request.user.__class__,
                            request=request, user=request.user)

        return instance, iscreate