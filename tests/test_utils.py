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

import unittest
from datetime import datetime
from repoze.what.plugins.x509.utils import *
from tests import TestX509Base


class TestUtils(TestX509Base):
    """Unit tests for the tools of this plugin"""

    def test_normal_distinguished_name_parse(self):
        dn = self.generate_dn(
            CN='common name',
            O='organization',
            OU='organization unit',
            C='co',
            ST='state',
            L='locality'
        )
        
        parsed = parse_dn(dn)
        self.assertEqual('common name', parsed['CN'][0])
        self.assertEqual('organization', parsed['O'][0])
        self.assertEqual('organization unit', parsed['OU'][0])
        self.assertEqual('co', parsed['C'][0])
        self.assertEqual('state', parsed['ST'][0])
        self.assertEqual('locality', parsed['L'][0])

    def test_verify_correct_certificate(self):
        issuer = {}
        subject = {}
        environ = self.make_environ(issuer, subject)
        assert verify_certificate(
            environ,
            'SSL_CLIENT_VERIFY',
            'SSL_CLIENT_V_START',
            'SSL_CLIENT_V_END'
        )


