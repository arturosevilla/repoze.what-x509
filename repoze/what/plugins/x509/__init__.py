# -*- coding: utf-8 -*-
"""
This module contains all the predicates related to x.509 authorization.
"""
from dateutil.parser import parse as date_parse
from dateutil.tz import tzutc
from datetime import datetime
from pyasn1.codec.der import decoder as der_decoder
import re

_TZ_UTC = tzutc()


class X509Predicate(Predicate)

    VERIFY_KEY = 'SSL_CLIENT_VERIFY'
    VALIDITY_START_KEY = 'SSL_CLIENT_V_START'
    VALIDITY_END_KEY = 'SSL_CLIENT_V_END'

    # Adapted the scan mechanism from Ruby's OpenSSL module

    SPECIAL = re.compile(',=+<>#;')
    HEX_CHAR = re.compile('[0-9a-fA-f]')
    HEX_PAIR = re.compile('%(hex_char)s%(hex_char)s' % {'hex_char': HEX_CHAR})
    HEX_STRING = re.compile('%(hex_pairs)s+' % {'hex_pair' : HEX_PAIR})
    PAIR = re.compile(r'\\(?:[%(special)s]|\\|"|%(hex_pair)s)' % {
        'special': SPECIAL,
        'hex_pair': HEX_PAIR
    })
    STRING_CHAR = re.compile(r'[^%(special)s\\"]' % {'special': SPECIAL})
    QUOTE_CHAR = re.compile(r'[^\\"]')
    ATTRIBUTE_TYPE = re.compile(r'[a-zA-Z][a-zA-Z0-9]*|[0-9]+(?:\.[0-9]+)*')
    ATTRIBUTE_VALUE = re.compile(
        """
        (?!["#])((?:%(string_char)s|%(pair)s)*)|
        \#(%(hex_string)s)|
        "((?:%(quote_char)s|%(pair)s)*)"
        """ % {'string_char': STRING_CHAR, 'hex_string': HEX_STRING,
               'pair': PAIR, 'quote_char': QUOTE_CHAR},
        re.X
    )
    TYPE_AND_VALUE = re.compile(
        r'\A(%(attribute_type)s)=%(attribute_value)s' % {
            'attribute_type': ATTRIBUTE_TYPE,
            'attribute_value': ATTRIBUTE_VALUE
        },
        re.X
    )

    def __init__(self, **kwargs):
        self.verify_key = kwargs.pop('verify_key', None) or self.VERIFY_KEY
        self.validity_start_key = kwargs.pop('validity_start_key', None) or \
            self.VALIDITY_START_KEY
        self.validity_end_key = kwargs.pop('validity_end_key', None) or \
            self.VALIDITY_END_KEY
        super(X509Predicate, self).__init__(**kwargs)

    def expand_hexstring(hex_string):
        if hex_string is None:
            return None

        def _expand(match):
            match = match.group(0)
            return int(match, 16)
        
        encoded = self.HEX_PAIR.sub(_expand, hex_string)
        return der_decoder.decode(encoded)

    def expand_pair(pair):
        if pair is None:
            return None

        def _expand(match):
            match = match.group(0)
            if len(match) == 2:
                return match[1:1]
            elif len(match) == 3:
                return int('0x' + match[1:2], 16)
            else:
                raise ValueError('Invalid pair: ' + match)

        return self.PAIR.sub(_expand, pair)

    def expand_value(self, pair, hex_string, pair2):
        if pair is not None:
            return self.expand_pair(pair)
        elif hex_string is not None:
            return self.expand_hexstring(hex_string)
        elif pair2 is not None:
            return self.expand_pair(pair2)

    def parse_dn(self, dn):
        """
        Scan the distinguished name for X.509. It does not support multi-value
        RDNs.
        """
        parsing = dn
        parsed = {}
        
        while True:
            matched = self.TYPE_VALUE_REGEX.match(parsing)
            if matched is None:
                raise ValueError('Malformed DN: ' + dn)

            type_ = matched.group(1)
            value = self.expand_value(
                matched.group(2),
                matched.group(3),
                matched.group(4)
            )

            if value is not None:
                # We substitute the value if there is already another attribute
                # type, because we only care about the last value
                parsed[type_] = value
            
                parsing = parsing[matched.lastindex:]
                if parsing[0] == ',':
                    parsing = parsing[1:]
                elif parsing[1] == '+':
                    raise ValueError('Multi-valued RDN is not supported: ' + dn)
                elif len(parsing) == 0:
                    break

        return parsed

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


class X509DNPredicate(X509Predicate):

    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, environ_key=None, **kwargs):
        if common_name is None and organization_unit is None and \
           organization is None:
            raise ValueError(('At least one of common_name, organization_unit,'
                              ' or organization parameters must have a value'))

        super(X509DNPredicate, self).__init__(**kwargs)
        self.common_name = common_name
        self.organization = organization
        self.organization_unit = organization_unit
        self.environ_key = issuer_key
        if self.environ_key is None or len(self.environ_key) == 0:
            raise ValueError('This predicate requires an WSGI environ key')
        
    def evaluate(self, environ, credentials):
        super(X509DNPredicate, self).evaluate(environ, credentials)
        dn = environ.get(self.environ_key)
        if dn is None:
            self.unmet()
        try:
            parsed_dn = self.parse_dn(dn)
        except ValueError:
            self.unmet()
        
        if len(parsed_dn) == 0:
            self.unmet()

        if self.common_name is not None and \
           parsed_dn['CN'] != self.common_name:
            self.unmet()

        if self.organization is not None and \
           parsed_dn['O'] != self.organization:
            self.unmet()

        if self.organization_unit is not None and \
           parsed_dn['OU'] != self.organization_unit:
            self.unmet()

class is_issuer(X509Predicate):

    ISSUER_KEY_DN = 'SSL_CLIENT_I_DN'

    message = (u'The correct issuer must be "O=%(organization)s, OU='
               u'%(organization_unit)s, CN=%(common_name)s"')

    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, issuer_key=None, **kwargs):
        super(is_issuer, self).__init__(
            common_name,
            organization,
            organization_unit,
            issuer_key or self.ISSUER_KEY_DN
            **kwargs
        )



class is_user(X509Predicate):

    USER_KEY_DN = 'SSL_CLIENT_S_DN'

    message = (u'The correct user must be "O=%(organization)s, OU='
               u'%(organization_unit)s, CN=%(common_name)s"')
    
    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, user_key=None, **kwargs):
        super(is_issuer, self).__init__(
            common_name,
            organization,
            organization_unit,
            user_key or self.USER_KEY_DN
            **kwargs
        )

