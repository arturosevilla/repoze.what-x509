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
This module contains utilities related to repoze what x509 plugin.
"""

from dateutil.parser import parse as date_parse
from dateutil.tz import tzutc
from datetime import datetime
import re


VERIFY_KEY = 'SSL_CLIENT_VERIFY'
VALIDITY_START_KEY = 'SSL_CLIENT_V_START'
VALIDITY_END_KEY = 'SSL_CLIENT_V_END'

# Adapted the scan mechanism from Ruby's OpenSSL module
_DN_SSL_REGEX = re.compile('\\s*([^\\/,]+)\\s*')

_TZ_UTC = tzutc()


__all__ = ['parse_dn', 'verify_certificate', 'VERIFY_KEY',
           'VALIDITY_START_KEY', 'VALIDITY_END_KEY']

def parse_dn(dn):
    """
    Parses a OpenSSL-like distinguished name into a dictionary. The keys are
    the attribute types and the values are lists (multiple values for that
    type).

    "Multi-values" are not supported (e.g., O=company+CN=name).
    """
    parsed = {}
    for match in _DN_SSL_REGEX.finditer(dn):
        type_, value = match.group(0).split('=', 2)
        if type_ not in parsed:
            parsed[type_] = []
        parsed[type_].append(value)

    return parsed


def verify_certificate(environ, verify_key, validity_start_key,
                       validity_end_key):
    """
    Checks if the client certificate is valid. Start and end data is optional,
    as not all SSL mods give that information.
    """
    verified = environ.get(verify_key)
    validity_start = environ.get(validity_start_key)
    validity_end = environ.get(validity_end_key)
    if verified != 'SUCCESS':
        return False

    if validity_start is None or validity_end is None:
        return True

    validity_start = date_parse(validity_start)
    validity_end = date_parse(validity_end)

    if validity_start.tzinfo != _TZ_UTC or validity_end.tzinfo != _TZ_UTC:
        # Can't consider other timezones
        return False

    now = datetime.utcnow().replace(tzinfo=_TZ_UTC)
    return validity_start <= now <= validity_end

