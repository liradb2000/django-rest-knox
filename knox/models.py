from django.conf import settings
from django.db import models
from django.utils import timezone

from knox import crypto
from knox.settings import CONSTANTS, knox_settings

User = settings.AUTH_USER_MODEL


class AuthTokenManager(models.Manager):
    def update_or_create(self, user, expiry=knox_settings.TOKEN_TTL):
        token = crypto.create_token_string()
        digest = crypto.hash_token(token)

        if expiry is not None:
            expiry = timezone.now() + expiry

        token_instance, create = super(AuthTokenManager, self).update_or_create(user=user, defaults={"token_key":token[:CONSTANTS.TOKEN_KEY_LENGTH], "digest": digest, "expiry":expiry})
        setattr(token_instance, "token", token)
        setattr(token_instance, "user", user)

        return token_instance, create


class AuthToken(models.Model):

    objects = AuthTokenManager()

    digest = models.CharField(
        max_length=CONSTANTS.DIGEST_LENGTH, unique=True)
    token_key = models.CharField(
        max_length=CONSTANTS.TOKEN_KEY_LENGTH, db_index=True)
    user = models.ForeignKey(User, null=False, blank=False,
                             related_name='auth_token_set', on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return '%s : %s' % (self.digest, self.user)
