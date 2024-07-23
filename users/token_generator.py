from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.conf import settings

class CustomTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
    secret = settings.SECRET_KEY

    def _make_hash_value(self, user, timestamp):
        login_timestamp = '' if user.last_login is None else user.last_login.replace(microsecond=0, tzinfo=None)
        return str(user.pk) + user.password + str(login_timestamp) + str(timestamp)

    def check_token(self, user, token):
        if not (user and token):
            return False

        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = self._num_seconds(self._now()) - int(ts_b36, 36)
        except ValueError:
            return False

        # Check token expiration (1 day)
        if ts > settings.PASSWORD_RESET_TIMEOUT_DAYS * 86400:
            return False

        return super().check_token(user, token)

# Instantiate the custom token generator
custom_token_generator = CustomTokenGenerator()