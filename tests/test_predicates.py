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

from dateutil.relativedelta import relativedelta
from dateutil.tz import tzutc
from datetime import datetime
import locale
import unittest

from repoze.what.plugins.x509 import is_issuer, is_subject, X509Predicate


class TestX509Base(unittest.TestCase):
    """Base class for testing X509 predictes"""

    def generate_dn(self, **kwargs):
        return ', '.join([t + '=' +  v for t, v in kwargs.iteritems()])

    def make_environ(self, issuer_dict, subject_dict, start=None, end=None,
                     verified=True,
                     verify_key='SSL_CLIENT_VERIFY',
                     validity_start_key='SSL_CLIENT_V_START',
                     validity_end_key='SSL_CLIENT_V_END',
                     issuer_key='SSL_CLIENT_I_DN',
                     subject_key='SSL_CLIENT_S_DN'):
        # By default consider that our certificate was signed a month ago for
        # the common validity of one year.
        if start is None:
            start = datetime.utcnow() + relativedelta(months=-1)
            start = start.replace(tzinfo=tzutc())
        if end is None:
            end = (datetime.utcnow() + relativedelta(months=11))
            end = start.replace(tzinfo=tzutc())

        locale.setlocale(locale.LC_ALL, 'en_US.utf8')
        datefmt = '%b %d %H:%M:%S %Y %Z'
        start, end = start.strftime(datefmt), end.strftime(datefmt)

        environ[verify_key] = verified
        environ[validity_start_key] = start
        environ[validity_end_key] = end
        environ[issuer_key] = self.generate_dn(**issuer_dict)
        environ[subject_key] = self.generate_dn(**subject_dict)

        return environ

    # Taken from repoze.what test suites

    def eval_met_predicate(self, p, environ):
        self.assertEqual(p.check_authorization(environ), None)
        self.assertEqual(p.is_met(environ), True)

    def eval_unmet_predicate(self, p, environ, expected_error):
        # should be None either way. We don't test for credentials
        credentials = environ.get('repoze.what.credentials')
        try:
            p.evaluate(environ, credentials)
        except predicates.NotAuthorizedError, error:
            self.assertEqual(unicode(error), expected_error)

        self.assertEqual(p.is_met(environ), False)


class TestIsUser(TestX509Base):
    pass


class TestIsIssuer(TestX509Base):
    pass
