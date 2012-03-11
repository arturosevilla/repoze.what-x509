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
Repoze what x509 plugin. It contains support for an identifier implementation
and predicates.
"""

from zope.interface import implements as zope_implements
from repoze.who.interfaces import IIdentifier

from .predicates import *
from .utils import *


__all__ = ['is_issuer', 'is_subject', 'X509Identifier']


class X509Identifier(object):
    """
    IIdentifier for HTTP requests with client certificates.
    """
    zope_implements(IIdentifier)

    classifications = { IIdentifier: ['browser'] }

    def __init__(self, subject_dn_key, login_field='Email',
                 multiple_values=False, verify_key=VERIFY_KEY,
                 start_key=VALIDITY_START_KEY, end_key=VALIDITY_END_KEY,
                 classifications=None):
        """
        """
        self.subject_dn_key = subject_dn_key
        self.login_field = login_field
        self.verify_key = verify_key
        self.start_key = start_key
        self.end_key = end_key
        self.multiple_values = multiple_values
        if classifications is not None:
            self.classifications = classifications

    # IIdentifier
    def identify(self, environ):
        """
        Gets the credentials for this request.
        """
        subject_dn = environ.get(self.subject_dn_key)
        if subject_dn is None or not verify_certificate(
            environ,
            self.verify_key,
            self.start_key,
            self.end_key
        ):
            return None

        creds = {'subject': subject_dn }
        # First let's try with Apache-like var name, if None then parse the DN
        key = self.subject_dn_key + '_' + self.login_field
        login = environ.get(key)
        if login is None:
            try:
                login = parse_dn(subject_dn)[self.login_field]
            except:
                login = None
        else:
            logins = []
            try:
                n = 0
                while True:
                    logins.append(environ[key + '_' + n])
                    n += 1
            except KeyError:
                pass
            
            if n == 0:
                login = [login]
            else:
                login = logins
                

        if login is None:
            return None

        if not self.multiple_values and len(login) > 1:
            return None
        elif not self.multiple_values:
            creds['login'] = login[0]
        else:
            creds['login'] = login

        return creds

