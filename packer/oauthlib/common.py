# -*- coding: utf-8 -*-
"""
oauthlib.common
~~~~~~~~~~~~~~

This module provides data structures and utilities common
to all implementations of OAuth.
"""
from __future__ import absolute_import, unicode_literals

import collections
import datetime
import logging
import random
import re
import sys
import time
from calendar import timegm

from jwcrypto.jwk import JWK as _JWK
from jwcrypto.jwt import JWT
from jwcrypto.common import json_decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey)

try:
    from urllib import quote as _quote
    from urllib import unquote as _unquote
    from urllib import urlencode as _urlencode
except ImportError:
    from urllib.parse import quote as _quote
    from urllib.parse import unquote as _unquote
    from urllib.parse import urlencode as _urlencode
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

# Copy code from jwcrypto 0.3.2, we need JWK.from_pyca()
from cryptography.hazmat.primitives.asymmetric import rsa
class JWK(_JWK):
    def __init__(self, **kwargs):
        self._params = dict()
        self._key = dict()
        self._unknown = dict()

        if 'generate' in kwargs:
            self.generate_key(**kwargs)
        elif kwargs:
            self.import_key(**kwargs)

    def _import_pyca_pri_rsa(self, key, **params):
        pn = key.private_numbers()
        params.update(
            kty='RSA',
            n=self._encode_int(pn.public_numbers.n),
            e=self._encode_int(pn.public_numbers.e),
            d=self._encode_int(pn.d),
            p=self._encode_int(pn.p),
            q=self._encode_int(pn.q),
            dp=self._encode_int(pn.dmp1),
            dq=self._encode_int(pn.dmq1),
            qi=self._encode_int(pn.iqmp)
        )
        self.import_key(**params)

    def _import_pyca_pub_rsa(self, key, **params):
        pn = key.public_numbers()
        params.update(
            kty='RSA',
            n=self._encode_int(pn.n),
            e=self._encode_int(pn.e)
        )
        self.import_key(**params)

    def _import_pyca_pri_ec(self, key, **params):
        pn = key.private_numbers()
        params.update(
            kty='EC',
            crv=JWKpycaCurveMap[key.curve.name],
            x=self._encode_int(pn.public_numbers.x),
            y=self._encode_int(pn.public_numbers.y),
            d=self._encode_int(pn.private_value)
        )
        self.import_key(**params)

    def _import_pyca_pub_ec(self, key, **params):
        pn = key.public_numbers()
        params.update(
            kty='EC',
            crv=JWKpycaCurveMap[key.curve.name],
            x=self._encode_int(pn.x),
            y=self._encode_int(pn.y),
        )
        self.import_key(**params)

    def import_from_pyca(self, key):
        if isinstance(key, rsa.RSAPrivateKey):
            self._import_pyca_pri_rsa(key)
        elif isinstance(key, rsa.RSAPublicKey):
            self._import_pyca_pub_rsa(key)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            self._import_pyca_pri_ec(key)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            self._import_pyca_pub_ec(key)
        else:
            raise InvalidJWKValue('Unknown key object %r' % key)

    @classmethod
    def from_pyca(cls, key):
        obj = cls()
        obj.import_from_pyca(key)
        return obj

UNICODE_ASCII_CHARACTER_SET = ('abcdefghijklmnopqrstuvwxyz'
                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                               '0123456789')

CLIENT_ID_CHARACTER_SET = (r' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMN'
                           'OPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}')

SANITIZE_PATTERN = re.compile(r'([^&;]*(?:password|token)[^=]*=)[^&;]+', re.IGNORECASE)
INVALID_HEX_PATTERN = re.compile(r'%[^0-9A-Fa-f]|%[0-9A-Fa-f][^0-9A-Fa-f]')

always_safe = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
               'abcdefghijklmnopqrstuvwxyz'
               '0123456789' '_.-')

log = logging.getLogger('oauthlib')

PY3 = sys.version_info[0] == 3

if PY3:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str


# 'safe' must be bytes (Python 2.6 requires bytes, other versions allow either)
def quote(s, safe=b'/'):
    s = s.encode('utf-8') if isinstance(s, unicode_type) else s
    s = _quote(s, safe)
    # PY3 always returns unicode.  PY2 may return either, depending on whether
    # it had to modify the string.
    if isinstance(s, bytes_type):
        s = s.decode('utf-8')
    return s


def unquote(s):
    s = _unquote(s)
    # PY3 always returns unicode.  PY2 seems to always return what you give it,
    # which differs from quote's behavior.  Just to be safe, make sure it is
    # unicode before we return.
    if isinstance(s, bytes_type):
        s = s.decode('utf-8')
    return s


def urlencode(params):
    utf8_params = encode_params_utf8(params)
    urlencoded = _urlencode(utf8_params)
    if isinstance(urlencoded, unicode_type):  # PY3 returns unicode
        return urlencoded
    else:
        return urlencoded.decode("utf-8")


def encode_params_utf8(params):
    """Ensures that all parameters in a list of 2-element tuples are encoded to
    bytestrings using UTF-8
    """
    encoded = []
    for k, v in params:
        encoded.append((
            k.encode('utf-8') if isinstance(k, unicode_type) else k,
            v.encode('utf-8') if isinstance(v, unicode_type) else v))
    return encoded


def decode_params_utf8(params):
    """Ensures that all parameters in a list of 2-element tuples are decoded to
    unicode using UTF-8.
    """
    decoded = []
    for k, v in params:
        decoded.append((
            k.decode('utf-8') if isinstance(k, bytes_type) else k,
            v.decode('utf-8') if isinstance(v, bytes_type) else v))
    return decoded


urlencoded = set(always_safe) | set('=&;:%+~,*@!()/?')


def urldecode(query):
    """Decode a query string in x-www-form-urlencoded format into a sequence
    of two-element tuples.

    Unlike urlparse.parse_qsl(..., strict_parsing=True) urldecode will enforce
    correct formatting of the query string by validation. If validation fails
    a ValueError will be raised. urllib.parse_qsl will only raise errors if
    any of name-value pairs omits the equals sign.
    """
    # Check if query contains invalid characters
    if query and not set(query) <= urlencoded:
        error = ("Error trying to decode a non urlencoded string. "
                 "Found invalid characters: %s "
                 "in the string: '%s'. "
                 "Please ensure the request/response body is "
                 "x-www-form-urlencoded.")
        raise ValueError(error % (set(query) - urlencoded, query))

    # Check for correctly hex encoded values using a regular expression
    # All encoded values begin with % followed by two hex characters
    # correct = %00, %A0, %0A, %FF
    # invalid = %G0, %5H, %PO
    if INVALID_HEX_PATTERN.search(query):
        raise ValueError('Invalid hex encoding in query string.')

    # We encode to utf-8 prior to parsing because parse_qsl behaves
    # differently on unicode input in python 2 and 3.
    # Python 2.7
    # >>> urlparse.parse_qsl(u'%E5%95%A6%E5%95%A6')
    # u'\xe5\x95\xa6\xe5\x95\xa6'
    # Python 2.7, non unicode input gives the same
    # >>> urlparse.parse_qsl('%E5%95%A6%E5%95%A6')
    # '\xe5\x95\xa6\xe5\x95\xa6'
    # but now we can decode it to unicode
    # >>> urlparse.parse_qsl('%E5%95%A6%E5%95%A6').decode('utf-8')
    # u'\u5566\u5566'
    # Python 3.3 however
    # >>> urllib.parse.parse_qsl(u'%E5%95%A6%E5%95%A6')
    # u'\u5566\u5566'
    query = query.encode(
        'utf-8') if not PY3 and isinstance(query, unicode_type) else query
    # We want to allow queries such as "c2" whereas urlparse.parse_qsl
    # with the strict_parsing flag will not.
    params = urlparse.parse_qsl(query, keep_blank_values=True)

    # unicode all the things
    return decode_params_utf8(params)


def extract_params(raw):
    """Extract parameters and return them as a list of 2-tuples.

    Will successfully extract parameters from urlencoded query strings,
    dicts, or lists of 2-tuples. Empty strings/dicts/lists will return an
    empty list of parameters. Any other input will result in a return
    value of None.
    """
    if isinstance(raw, bytes_type) or isinstance(raw, unicode_type):
        try:
            params = urldecode(raw)
        except ValueError:
            params = None
    elif hasattr(raw, '__iter__'):
        try:
            dict(raw)
        except ValueError:
            params = None
        except TypeError:
            params = None
        else:
            params = list(raw.items() if isinstance(raw, dict) else raw)
            params = decode_params_utf8(params)
    else:
        params = None

    return params


def generate_nonce():
    """Generate pseudorandom nonce that is unlikely to repeat.

    Per `section 3.3`_ of the OAuth 1 RFC 5849 spec.
    Per `section 3.2.1`_ of the MAC Access Authentication spec.

    A random 64-bit number is appended to the epoch timestamp for both
    randomness and to decrease the likelihood of collisions.

    .. _`section 3.2.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-3.2.1
    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode_type(unicode_type(random.getrandbits(64)) + generate_timestamp())


def generate_timestamp():
    """Get seconds since epoch (UTC).

    Per `section 3.3`_ of the OAuth 1 RFC 5849 spec.
    Per `section 3.2.1`_ of the MAC Access Authentication spec.

    .. _`section 3.2.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-3.2.1
    .. _`section 3.3`: http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return unicode_type(int(time.time()))


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = random.SystemRandom()
    return ''.join(rand.choice(chars) for x in range(length))


def get_rsa_private_key(data):
    if isinstance(data, (bytes_type, unicode_type)):
        if isinstance(data, unicode_type):
            data = data.encode('ascii')
        # load_pem_private_key() requires the data to be str or bytes
        private_key = load_pem_private_key(data, None, default_backend())
    else:
        private_key = data

    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("Expected RSAPrivateKey, but got %s" %
                        private_key.__class__.__name__)

    return private_key


def get_rsa_public_key(data):
    if isinstance(data, (bytes_type, unicode_type)):
        if isinstance(data, unicode_type):
            data = data.encode('ascii')
        # load_pem_public_key() requires the data to be str or bytes
        public_key = load_pem_public_key(data, default_backend())
    else:
        public_key = data

    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("Expected RSAPublicKey, but got %s" %
                        public_key.__class__.__name__)

    return public_key


def normalize_claims(claims):
    for claim in ['exp', 'iat', 'nbf']:
        # Convert datetime to a intDate value in known time-format claims
        if isinstance(claims.get(claim), datetime.datetime):
            claims[claim] = timegm(claims[claim].utctimetuple())
    return claims


def generate_jwt_assertion(private_key, claims):
    rsa_private_key = get_rsa_private_key(private_key)
    jwkey = JWK.from_pyca(rsa_private_key)
    token = JWT(header={'alg': 'RS256'}, claims=normalize_claims(claims))
    token.make_signed_token(jwkey)
    return to_unicode(token.serialize(), "UTF-8")


def generate_signed_token(private_pem, request):
    now = datetime.datetime.utcnow()
    claims = {
        'scope': request.scope,
        'exp': now + datetime.timedelta(seconds=request.expires_in)
    }
    claims.update(request.claims)
    return generate_jwt_assertion(private_pem, claims)


def verify_signed_token(public_key, token):
    rsa_public_key = get_rsa_public_key(public_key)
    jwkey = JWK.from_pyca(rsa_public_key)
    signed_token = JWT(key=jwkey, jwt=token)
    return json_decode(signed_token.claims)


def generate_client_id(length=30, chars=CLIENT_ID_CHARACTER_SET):
    """Generates an OAuth client_id

    OAuth 2 specify the format of client_id in
    http://tools.ietf.org/html/rfc6749#appendix-A.
    """
    return generate_token(length, chars)


def add_params_to_qs(query, params):
    """Extend a query with a list of two-tuples."""
    if isinstance(params, dict):
        params = params.items()
    queryparams = urlparse.parse_qsl(query, keep_blank_values=True)
    queryparams.extend(params)
    return urlencode(queryparams)


def add_params_to_uri(uri, params, fragment=False):
    """Add a list of two-tuples to the uri query components."""
    sch, net, path, par, query, fra = urlparse.urlparse(uri)
    if fragment:
        fra = add_params_to_qs(fra, params)
    else:
        query = add_params_to_qs(query, params)
    return urlparse.urlunparse((sch, net, path, par, query, fra))


def safe_string_equals(a, b):
    """ Near-constant time string comparison.

    Used in order to avoid timing attacks on sensitive information such
    as secret keys during request verification (`rootLabs`_).

    .. _`rootLabs`: http://rdist.root.org/2010/01/07/timing-independent-array-comparison/

    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def to_unicode(data, encoding='UTF-8'):
    """Convert a number of different types of objects to unicode."""
    if isinstance(data, unicode_type):
        return data

    if isinstance(data, bytes_type):
        return unicode_type(data, encoding=encoding)

    if hasattr(data, '__iter__'):
        try:
            dict(data)
        except TypeError:
            pass
        except ValueError:
            # Assume it's a one dimensional data structure
            return (to_unicode(i, encoding) for i in data)
        else:
            # We support 2.6 which lacks dict comprehensions
            if hasattr(data, 'items'):
                data = data.items()
            return dict(((to_unicode(k, encoding), to_unicode(v, encoding)) for k, v in data))

    return data


class CaseInsensitiveDict(dict):

    """Basic case insensitive dict with strings only keys."""

    proxy = {}

    def __init__(self, data):
        self.proxy = dict((k.lower(), k) for k in data)
        for k in data:
            self[k] = data[k]

    def __contains__(self, k):
        return k.lower() in self.proxy

    def __delitem__(self, k):
        key = self.proxy[k.lower()]
        super(CaseInsensitiveDict, self).__delitem__(key)
        del self.proxy[k.lower()]

    def __getitem__(self, k):
        key = self.proxy[k.lower()]
        return super(CaseInsensitiveDict, self).__getitem__(key)

    def get(self, k, default=None):
        return self[k] if k in self else default

    def __setitem__(self, k, v):
        super(CaseInsensitiveDict, self).__setitem__(k, v)
        self.proxy[k.lower()] = k


class Request(object):

    """A malleable representation of a signable HTTP request.

    Body argument may contain any data, but parameters will only be decoded if
    they are one of:

    * urlencoded query string
    * dict
    * list of 2-tuples

    Anything else will be treated as raw body data to be passed through
    unmolested.
    """

    def __init__(self, uri, http_method='GET', body=None, headers=None,
                 encoding='utf-8'):
        # Convert to unicode using encoding if given, else assume unicode
        encode = lambda x: to_unicode(x, encoding) if encoding else x

        self.uri = encode(uri)
        self.http_method = encode(http_method)
        self.headers = CaseInsensitiveDict(encode(headers or {}))
        self.body = encode(body)
        self.decoded_body = extract_params(self.body)
        self.oauth_params = []
        self.validator_log = {}

        self._params = {
            "access_token": None,
            "client": None,
            "client_id": None,
            "client_secret": None,
            "code": None,
            "extra_credentials": None,
            "grant_type": None,
            "redirect_uri": None,
            "refresh_token": None,
            "request_token": None,
            "response_type": None,
            "scope": None,
            "scopes": None,
            "state": None,
            "token": None,
            "user": None,
            "token_type_hint": None,

            # OpenID Connect
            "response_mode": None,
            "nonce": None,
            "display": None,
            "prompt": None,
            "claims": None,
            "max_age": None,
            "ui_locales": None,
            "id_token_hint": None,
            "login_hint": None,
            "acr_values": None
        }
        self._params.update(dict(urldecode(self.uri_query)))
        self._params.update(dict(self.decoded_body or []))
        self._params.update(self.headers)

    def __getattr__(self, name):
        if name in self._params:
            return self._params[name]
        else:
            raise AttributeError(name)

    def __repr__(self):
        body = self.body
        headers = self.headers.copy()
        if body:
            body = SANITIZE_PATTERN.sub('\1<SANITIZED>', str(body))
        if 'Authorization' in headers:
            headers['Authorization'] = '<SANITIZED>'
        return '<oauthlib.Request url="%s", http_method="%s", headers="%s", body="%s">' % (
            self.uri, self.http_method, headers, body)

    @property
    def uri_query(self):
        return urlparse.urlparse(self.uri).query

    @property
    def uri_query_params(self):
        if not self.uri_query:
            return []
        return urlparse.parse_qsl(self.uri_query, keep_blank_values=True,
                                  strict_parsing=True)

    @property
    def duplicate_params(self):
        seen_keys = collections.defaultdict(int)
        all_keys = (p[0]
                    for p in (self.decoded_body or []) + self.uri_query_params)
        for k in all_keys:
            seen_keys[k] += 1
        return [k for k, c in seen_keys.items() if c > 1]
