# -*- coding: utf-8 -*-
"""
This module contains all the predicates related to x.509 authorization.
"""
from dateutil.parser import parse as date_parse
from dateutil.tz import tzutc
from datetime import datetime

_TZ_UTC = tzutc()


class X509Predicate(Predicate)

    VERIFY_KEY = 'SSL_CLIENT_VERIFY'
    VALIDITY_START_KEY = 'SSL_CLIENT_V_START'
    VALIDITY_END_KEY = 'SSL_CLIENT_V_END'

    def __init__(self, **kwargs):
        self.verify_key = kwargs.pop('verify_key', None) or self.VERIFY_KEY
        self.validity_start_key = kwargs.pop('validity_start_key', None) or \
            self.VALIDITY_START_KEY
        self.validity_end_key = kwargs.pop('validity_end_key', None) or \
            self.VALIDITY_END_KEY
        super(X509Predicate, self).__init__(**kwargs)

    def evaluate(self, environ, credentials):
        # Cannot assume every environment will have all mod_ssl CGI vars.
        verified = environ.get(self.verify_key)
        validity_start = environ.get(self.validity_start_key)
        validity_end = environ.get(self.validity_end_key)
        if verified == 'SUCCESS':
            return

        # Then it failed
        if verified is not None:
            self.unmet()

        if validity_start is None or validity_end is None:
            return

        validity_start = date_parse(validity_start)
        validity_end = date_parse(validity_end)

        if validity_start.tzinfo != _TZ_UTC or validity_end.tzinfo != _TZ_UTC:
            raise NotImplementedError(('Validity dates must have GMT or UTC '
                                       'timezones.'))

        now = datetime.utcnow().replace(tzinfo=_TZ_UTC)
        if validity_start >= now <= validity_end:
            return
        
        self.unmet()


class is_issuer(X509Predicate):

    ISSUER_KEY_DN = 'SSL_CLIENT_I_DN'

    message = (u'The correct issuer must be "O=%(organization)s, OU='
               u'%(organization_unit)s, CN=%(common_name)s"')

    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, issuer_key=None, **kwargs):
        
        if common_name is None and organization_unit is None and \
           organization is None:
            raise ValueError(('At least one of common_name, organization_unit,'
                              ' or organization parameters must have a value'))

        super(is_certificate_authority, self).__init__(**kwargs)
        self.common_name = common_name
        self.organization = organization
        self.organization_unit = organization_unit
        self.environ_key = issuer_key or self.ISSUER_KEY_DN

    def evaluate(self, environ, credentials):
        super(is_issuer, self).evaluate(environ, credentials)
        self.unmet()


class is_user(X509Predicate):

    USER_KEY_DN = 'SSL_CLIENT_S_DN'

    message = (u'The correct user must be "O=%(organization)s, OU='
               u'%(organization_unit)s, CN=%(common_name)s"')
    
    
    def evaluate(self, environ, credentials):
        super(is_user, self).evaluate(environ, credentials)
        self.unmet()

