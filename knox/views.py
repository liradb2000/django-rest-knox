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
from knox.mixins import KnoxLoginMixin

class LoginView(APIView, KnoxLoginMixin):
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        instance, _=self.create_token(request.user)
                            
        if knox_settings.USE_COOKIE:
            response_data = Response(self.get_post_response_data(request, instance.token[:CONSTANTS.TOKEN_KEY_LENGTH], instance))
            response_data= self.modify_response(response_data, instance)
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
