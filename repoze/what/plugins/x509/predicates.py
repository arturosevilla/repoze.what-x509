# -*- coding: utf-8 -*-
# Copyright (C) 2012 Ckluster Technologies
# All Rights Reserved.
#
# This software is subject to the provision stipulated in
# http://www.ckluster.com/OPEN_LICENSE.txt.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""
This module contains all the predicates related to x.509 authorization.
"""
from repoze.what.predicates import Predicate
from .utils import *
import re


__all__ = ['is_subject', 'is_issuer', 'X509Predicate', 'X509DNPredicate']


class X509Predicate(Predicate):

    def __init__(self, **kwargs):
        self.verify_key = kwargs.pop('verify_key', None) or VERIFY_KEY
        self.validity_start_key = kwargs.pop('validity_start_key', None) or \
            VALIDITY_START_KEY
        self.validity_end_key = kwargs.pop('validity_end_key', None) or \
            VALIDITY_END_KEY
        super(X509Predicate, self).__init__(**kwargs)

    def evaluate(self, environ, credentials):
        # Cannot assume every environment will have all mod_ssl CGI vars.
        if not verify_certificate(
            environ,
            self.verify_key,
            self.validity_start_key,
            self.validity_end_key
        ):
            self.unmet()


class X509DNPredicate(X509Predicate):

    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, country=None,
                 state=None, locality=None, environ_key=None, **kwargs):
        if common_name is None and organization_unit is None and \
           organization is None and country is None and state is None and \
           locality is None and len(kwargs) == 0:
            raise ValueError(('At least one of common_name, organization_unit,'
                              ' organization, country, state, locality, or one '
                              'custom parameter must have a value'))

        field_and_values = (
            ('O', organization, 'organization'),
            ('CN', common_name, 'common_name'),
            ('OU', organization_unit, 'organization_unit'),
            ('C', country, 'country'),
            ('ST', state, 'state'),
            ('L', locality, 'locality')
        )

        self._prepare_dn_params_with_consistency(
            field_and_values,
            kwargs
        )

        super(X509DNPredicate, self).__init__(**kwargs)

        if self.environ_key is None or len(self.environ_key) == 0:
            raise ValueError('This predicate requires a WSGI environ key')

    def _prepare_dn_params_with_consistency(self, check_params, kwargs):
        # We prefer common_name over CN, for example
        # It receives a 3-tuple: 
        # * The DN attribute type
        # * The value of the constructor parameter
        # * The name of the constructor parameter
        self.dn_params = []
        for param in check_params:
            if param[0] in kwargs and param[1] is not None:
                log.warn('Choosing %s over "%s"' % (param[0], param[1]))
                del kwargs[param[0]]

            if param[1] is not None:
                self.dn_params.append((param[0], param[1]))

        self.dn_params.extend(kwargs.iteritems())
        
    def evaluate(self, environ, credentials):
        super(X509DNPredicate, self).evaluate(environ, credentials)

        # First let's try with Apache-like server variables, and last rely on
        # the parsing of the DN itself.

        try:
            for suffix, value in self.dn_params:
                self._check_server_variable(environ, value, '_' + suffix)
        except KeyError:
            pass

        dn = environ.get(self.environ_key)
        if dn is None:
            self.unmet()

        try:
            parsed_dn = parse_dn(dn)
        except:
            self.unmet()
        
        if len(parsed_dn) == 0:
            self.unmet()

        try:
            for key, value in self.dn_params:
                self._check_parsed_dict(parsed_dn, key, value)
        except KeyError:
            self.unmet()

    def _check_parsed_dict(self, parsed, key, value):
        parsed_value = parsed[key]
        if isinstance(value, list) or isinstance(value, tuple):
            for v in value:
                if v not in parsed_value:
                    self.unmet()
        
        elif value not in parsed_value:
            self.unmet()

    def _check_server_variable(self, environ, suffix, value):
        key = self.environ_key + suffix
        if isinstance(value, list) or isinstance(value, tuple):
            environ_values = []
            for n in range(len(value)):
                environ_values.append(environ[self.environ_key + '_' + str(n)])

            for v in value:
                if v not in environ_values:
                    self.unmet()

        elif environ[key] != value:
            self.unmet()

class is_issuer(X509DNPredicate):

    ISSUER_KEY_DN = 'SSL_CLIENT_I_DN'

    message = 'Invalid SSL client issuer.'

    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, country=None, state=None,
                 locality=None, issuer_key=None, **kwargs):
        super(is_issuer, self).__init__(
            common_name,
            organization,
            organization_unit,
            country,
            state,
            locality,
            issuer_key or self.ISSUER_KEY_DN
            **kwargs
        )



class is_subject(X509DNPredicate):

    SUBJECT_KEY_DN = 'SSL_CLIENT_S_DN'

    message = 'Invalid SSL client subject.'
    
    def __init__(self, common_name=None, organization=None,
                 organization_unit=None, country=None, state=None,
                 locality=None, subject_key=None, **kwargs):
        super(is_issuer, self).__init__(
            common_name,
            organization,
            organization_unit,
            country,
            state,
            locality,
            subject_key or self.SUBJECT_KEY_DN
            **kwargs
        )

