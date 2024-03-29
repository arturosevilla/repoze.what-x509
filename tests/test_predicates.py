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
# CONTRACT, STRICT LIABITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from dateutil.relativedelta import relativedelta
from dateutil.tz import tzutc
from datetime import datetime

from tests import TestX509Base
from repoze.what.plugins.x509 import is_issuer, is_subject, X509DNPredicate 


class _TestDNBase(TestX509Base):

    PREDICATE = None

    def make_environ_for_test(self, to_test, not_to_test, **kwargs):
        raise NotImplementedError()

    def get_error_message(self):
        return self.PREDICATE.message

    def get_key_dn(self):
        raise NotImplementedError()

    def test_without_dn_value_in_environ(self):
        predicate = self.PREDICATE(common_name='name')
        environ = { 'SSL_CLIENT_VERIFY': 'SUCCESS' }
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_invalid_dn(self):
        predicate = self.PREDICATE(common_name='name')
        environ = self.make_environ_for_test(
            to_test='invalid dn',
            not_to_test={'CN': 'Name', 'C': 'US'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_dn_does_not_satisfy_predicate_incomplete(self):
        predicate = self.PREDICATE(C='US')
        environ = self.make_environ_for_test(
            to_test = {'CN': 'Name', 'O': 'Company'},
            not_to_test={'CN': 'Other', 'O': 'Company', 'C': 'US'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_construct_predicate_without_args(self):
        self.assertRaises(ValueError, self.PREDICATE)

    def test_construct_predicate_with_kwargs(self):
        predicate = self.PREDICATE(Email='email@example.com')
        assert isinstance(predicate, self.PREDICATE)

    def test_common_name(self):
        predicate = self.PREDICATE(common_name='NAME')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_common_name_server(self):
        predicate = self.PREDICATE(common_name='NAME')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Fail', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_CN'] = 'NAME'
        self.eval_met_predicate(predicate, environ)


    def test_multiple_common_name_server(self):
        predicate = self.PREDICATE(common_name=('NAME', 'Other'))
        environ = self.make_environ_for_test(
            to_test = '/CN=Nope/CN=Na/C=US/ST=California',
            not_to_test={'CN': 'Other', 'C': 'US'}
        )
        environ[self.get_key_dn() + '_CN_0'] = 'NAME'
        environ[self.get_key_dn() + '_CN_1'] = 'Other'
        self.eval_met_predicate(predicate, environ)

    def test_fail_multiple_common_name_server(self):
        predicate = self.PREDICATE(common_name=('NAME', 'Other'))
        environ = self.make_environ_for_test(
            to_test = '/CN=NAME/CN=Other/C=US/ST=California',
            not_to_test={'CN': 'Other', 'C': 'US'}
        )
        environ[self.get_key_dn() + '_CN_0'] = 'Nope'
        environ[self.get_key_dn() + '_CN_1'] = 'Other'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_multiple_common_name(self):
        predicate = self.PREDICATE(common_name=('NAME', 'Other'))
        environ = self.make_environ_for_test(
            to_test = '/CN=Fail/CN=Other/C=US/ST=California',
            not_to_test={'CN': 'Other', 'C': 'US'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_common_name(self):
        predicate = self.PREDICATE(common_name='Fail')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_common_name_server(self):
        predicate = self.PREDICATE(common_name='Fail')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Fail', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_CN'] = 'NAME'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_choose_common_name_over_CN(self):
        predicate = self.PREDICATE(common_name='Name', CN='CN')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_organization(self):
        predicate = self.PREDICATE(organization='ORG')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California', 'O': 'ORG'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_organization_server(self):
        predicate = self.PREDICATE(organization='ORG')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California', 'O': 'FAIL'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_O'] = 'ORG'
        self.eval_met_predicate(predicate, environ)

    def test_fail_organization(self):
        predicate = self.PREDICATE(organization='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California', 'O': 'ORG'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_organization_server(self):
        predicate = self.PREDICATE(organization='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California', 'O': 'FAIL'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_O'] = 'ORG'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_choose_organization_over_O(self):
        predicate = self.PREDICATE(organization='Company', O='Org')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_organizational_unit(self):
        predicate = self.PREDICATE(organizational_unit='Unit')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California',
                     'OU': 'Unit'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'OU': 'Unit'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_organizational_unit_server(self):
        predicate = self.PREDICATE(organizational_unit='Unit')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California',
                     'OU': 'FAIL'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'OU': 'Unit'}
        )
        environ[self.get_key_dn() + '_OU'] = 'Unit'
        self.eval_met_predicate(predicate, environ)

    def test_fail_organizational_unit(self):
        predicate = self.PREDICATE(organizational_unit='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California',
                     'OU': 'Unit'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'OU': 'Unit'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_organizational_unit_server(self):
        predicate = self.PREDICATE(organizational_unit='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'asdf', 'C': 'US', 'ST': 'California',
                     'OU': 'FAIL'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'OU': 'Unit'}
        )
        environ[self.get_key_dn() + '_OU'] = 'Unit'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_choose_organizational_unit_over_OU(self):
        predicate = self.PREDICATE(organizational_unit='Org U', OU='OU')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'OU': 'Org U'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_country(self):
        predicate = self.PREDICATE(country='US')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_country_server(self):
        predicate = self.PREDICATE(country='US')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'FA', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_C'] = 'US'
        self.eval_met_predicate(predicate, environ)

    def test_fail_country(self):
        predicate = self.PREDICATE(country='FA')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_country_server(self):
        predicate = self.PREDICATE(country='FA')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'FA', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_C'] = 'US'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())
    
    def test_choose_country_over_C(self):
        predicate = self.PREDICATE(country='US', C='MX')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'WE', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_state(self):
        predicate = self.PREDICATE(state='State')
        environ = self.make_environ_for_test(
            to_test={'CN': 'name', 'C': 'US', 'ST': 'State', 'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_state_server(self):
        predicate = self.PREDICATE(state='State')
        environ = self.make_environ_for_test(
            to_test={'CN': 'name', 'C': 'US', 'ST': 'Would fail', 'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_ST'] = 'State'
        self.eval_met_predicate(predicate, environ)

    def test_fail_state(self):
        predicate = self.PREDICATE(state='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'name', 'C': 'US', 'ST': 'State', 'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_state_server(self):
        predicate = self.PREDICATE(state='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'name', 'C': 'US', 'ST': 'FAIL', 'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_ST'] = 'State'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())


    def test_choose_state_over_ST(self):
        predicate = self.PREDICATE(state='California', ST='Washington')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'Oregon',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_locality(self):
        predicate = self.PREDICATE(locality='San Diego')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'L': 'San Diego'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'org', 'L': 'L'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_locality_server(self):
        predicate = self.PREDICATE(locality='San Diego')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'L': 'would fail'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'org', 'L': 'L'}
        )
        environ[self.get_key_dn() + '_L'] = 'San Diego'
        self.eval_met_predicate(predicate, environ)

    def test_fail_locality(self):
        predicate = self.PREDICATE(locality='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'L': 'San Diego'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'org', 'L': 'L'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_locality_server(self):
        predicate = self.PREDICATE(locality='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'L': 'FAIL'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'org', 'L': 'L'}
        )
        environ[self.get_key_dn() + '_L'] = 'San Diego'
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_choose_locality_over_L(self):
        predicate = self.PREDICATE(locality='San Diego', L='Tijuana')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'L': 'San Diego'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_additional_arguments(self):
        predicate = self.PREDICATE(Email='email', Other='other')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'Email': 'email', 'Other': 'other'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_additional_arguments_server(self):
        predicate = self.PREDICATE(Email='email', Other='other')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'Email': 'fail', 'Other': 'fail'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        environ[self.get_key_dn() + '_Email'] = 'email'
        environ[self.get_key_dn() + '_Other'] = 'other'
        self.eval_met_predicate(predicate, environ)

    def test_fail_additional_arguments(self):
        predicate = self.PREDICATE(Email='FAIL')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'Email': 'email', 'Other': 'other'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_fail_one_argument(self):
        predicate = self.PREDICATE(common_name='NAME', C='MX')
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company', 'Email': 'email', 'Other': 'other'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'}
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())

    def test_multiple_arguments(self):
        predicate = self.PREDICATE(common_name='Name', organization='Company')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'O': 'Company', 'ST': 'California',
                     'OU': 'Unit'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'Baja', 'O': 'Org'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_tuple_with_multiple_values_in_dn(self):
        predicate = self.PREDICATE(common_name=('Name', 'Other'))
        environ = self.make_environ_for_test(
            '/CN=Other/CN=Name/C=US/ST=California',
            {'CN': 'ASDF', 'C': 'US', 'O': 'Org'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_single_value_with_multiple_values_in_dn(self):
        predicate = self.PREDICATE(common_name='Name')
        environ = self.make_environ_for_test(
            '/CN=Other/CN=Name/C=US/ST=California',
            {'CN': 'ASDF', 'C': 'US', 'O': 'Org'}
        )
        self.eval_met_predicate(predicate, environ)

    def test_invalid_certificate(self):
        predicate = self.PREDICATE(common_name='Name')
        environ = self.make_environ_for_test(
            to_test={'CN': 'Name', 'O': 'Company', 'ST': 'California',
                     'OU': 'Unit'},
            not_to_test={'CN': 'Other', 'C': 'MX', 'ST': 'Baja', 'O': 'Org'},
            verified=False
        )
        self.eval_unmet_predicate(predicate, environ, self.get_error_message())


class TestIsSubject(_TestDNBase):

    PREDICATE = is_subject

    def make_environ_for_test(self, to_test, not_to_test, **kwargs):
        return self.make_environ(
            not_to_test,
            to_test,
            **kwargs
        )

    def get_key_dn(self):
        return is_subject.SUBJECT_KEY_DN

    def test_common_name_different_key(self):
        predicate = is_subject(
            common_name='NAME',
            subject_key='HTTP_SSL_CLIENT_S_DN'
        )
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'},
            prefix='HTTP_'
        )
        self.eval_met_predicate(predicate, environ)

    def test_common_name_different_key_server(self):
        predicate = is_subject(
            common_name='NAME',
            subject_key='HTTP_SSL_CLIENT_S_DN'
        )
        environ = self.make_environ_for_test(
            to_test={'CN': 'Fail', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'},
            prefix='HTTP_'
        )
        environ['HTTP_SSL_CLIENT_S_DN_CN'] = 'NAME'
        self.eval_met_predicate(predicate, environ)

class TestX509DNPredicate(TestX509Base):

    def test_invalid_subject_key(self):
        self.assertRaises(
            ValueError,
            X509DNPredicate,
            common_name='Name', # so we don't raise ValueError with no args
            environ_key=None
        )
        self.assertRaises(
            ValueError,
            X509DNPredicate,
            common_name='Name',
            environ_key=''
        )


class TestIsIssuer(_TestDNBase):

    PREDICATE = is_issuer

    def make_environ_for_test(self, to_test, not_to_test, **kwargs):
        return self.make_environ(
            to_test,
            not_to_test,
            **kwargs
        )

    def get_key_dn(self):
        return is_issuer.ISSUER_KEY_DN

    def test_common_name_different_key(self):
        predicate = is_issuer(
            common_name='NAME',
            issuer_key='HTTP_SSL_CLIENT_I_DN'
        )
        environ = self.make_environ_for_test(
            to_test={'CN': 'NAME', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'},
            prefix='HTTP_'
        )
        self.eval_met_predicate(predicate, environ)

    def test_common_name_different_key_server(self):
        predicate = is_issuer(
            common_name='NAME',
            issuer_key='HTTP_SSL_CLIENT_I_DN'
        )
        environ = self.make_environ_for_test(
            to_test={'CN': 'Fail', 'C': 'US', 'ST': 'California',
                     'O': 'Company'},
            not_to_test={'CN': 'Other', 'C': 'US', 'ST': 'California',
                         'O': 'Company'},
            prefix='HTTP_'
        )
        environ['HTTP_SSL_CLIENT_I_DN_CN'] = 'NAME'
        self.eval_met_predicate(predicate, environ)

