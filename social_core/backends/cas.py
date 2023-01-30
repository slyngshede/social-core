"""
CAS OIDC backend
https://apereo.github.io/cas/6.6.x/authentication/OIDC-Authentication.html

Backend for authenticating with Apereo CAS using OIDC. This backend handles
the minor implementation differences between the Apereo CAS OIDC server
implementation and the standard OIDC implementation in Python Social Auth.
"""

import logging

from social_core.utils import cache

from .open_id_connect import OpenIdConnectAuth

logger = logging.getLogger('idm')

class CASOpenIdConnectAuth(OpenIdConnectAuth):
    """
    Open ID Connect backends for use with Apereo CAS.
    Currently only the code response type is supported.

    It can also be directly instantiated as a generic OIDC backend.
    To use it you will need to set at minimum:

    SOCIAL_AUTH_CAS_OIDC_ENDPOINT = 'https://.....'  # endpoint without /.well-known/openid-configuration
    SOCIAL_AUTH_CAS_KEY = '<client_id>'
    SOCIAL_AUTH_CAS_SECRET = '<client_secret>'
    """

    name = "cas"
    # Override OIDC_ENDPOINT in your subclass to enable autoconfig of OIDC
    OIDC_ENDPOINT = None
    ID_TOKEN_MAX_AGE = 600
    DEFAULT_SCOPE = ["openid", "profile", "email"]
    EXTRA_DATA = ["id_token", "refresh_token", ("sub", "id")]
    REDIRECT_STATE = False
    ACCESS_TOKEN_METHOD = "POST"
    REVOKE_TOKEN_METHOD = "GET"
    ID_KEY = "sub"
    USERNAME_KEY = "preferred_username"
    JWT_ALGORITHMS = ["RS256"]
    JWT_DECODE_OPTIONS = dict()
    # When these options are unspecified, server will choose via openid autoconfiguration
    ID_TOKEN_ISSUER = ""
    ACCESS_TOKEN_URL = ""
    AUTHORIZATION_URL = ""
    REVOKE_TOKEN_URL = ""
    USERINFO_URL = ""
    JWKS_URI = ""
    TOKEN_ENDPOINT_AUTH_METHOD = ""

    def oidc_endpoint(self):
        logger.info(f'settings: {self.setting}')
        return self.setting("OIDC_ENDPOINT", self.OIDC_ENDPOINT)

    @cache(ttl=86400)
    def oidc_config(self):
        return self.get_json(self.oidc_endpoint() + "/.well-known/openid-configuration")

    def user_data(self, access_token, *args, **kwargs):
        data = self.get_json(
            self.userinfo_url(), headers={"Authorization": f"Bearer {access_token}"}
        )
        logger.info(f'user data: {data}')

        return data.get('attributes', {})

    def get_user_details(self, response):
        username_key = self.setting("USERNAME_KEY", self.USERNAME_KEY)
        attr = response.get('attributes', {})

        logger.info(f'attributes: {attr}')

        return {
            "username": attr.get(username_key),
            "email": attr.get("email"),
            "fullname": attr.get("name"),
            "first_name": attr.get("given_name"),
            "last_name": attr.get("family_name"),
        }