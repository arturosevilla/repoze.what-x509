************
Advanced Use
************

You can customize :mod:`repoze.what.plugins.x509` so that it works for your web
server. There is a simple customization example in :ref:`Headers modification
<headers>`.

In order to make the best out of the functionality of this plugin, you need to
know how it is that it reads the values from the WSGI environment, and the
rules for evaluation.

Rules for parameter specification
=================================

* When you create any distinguished name based predicate
  (any subclass of :py:class:`X509DNPredicate`), you can specify the fields
  that you need to check upon requests. The constructor accepts
  ``common_name``, ``organization``, ``organization_unit``, ``country``,
  ``state``, or ``locality``.
* The constructor can also accept any "custom" field that may be present in the
  distinguished name of the client certificate. You specify this fields by
  using the attribute type name as a keyword to the constructor. For example,
  if there is a field named "A", then you could construct a predicate as
  ``is_subject(A='some value')``.
* Please note that according to the last rule, you may also specify the
  defined constructor parameters by their equivalent attribute type names,
  such as, "CN" for common_name, or "O" for organization. However if you
  specify both of a type, the value that the predicate will check is the one
  that is present with the defined constructor arguments. For example,
  ``is_subject(organization='ABC', O='XYZ')`` will check for an organization
  named "ABC", not "XYZ".

Rules for predicate evaluation
==============================

1. The predicate will first look for the "verified" key in our WSGI
   environment. By default it will try to locate it in ``SSL_CLIENT_VERIFIED``,
   however you can change this behavior by specifying this key in the predicate
   constructor through the ``verify_key`` argument. If value is different than
   "SUCCESS", it will fail.
2. If the WSGI environment provides the validity time range of the certificate
   it will be checked. However, not all web servers set this variable in the
   headers. You can change the keys that the environment tries to check by
   setting ``validity_start_key`` and ``validity_end_key``.
3. After the first two validations, all :py:class:`X509DNPredicate` based
   predicates (:py:class:`is_issuer` and :py:class:`is_subject`) will check for
   server variables that tries to validate it. The keys for these variables
   will be constructed by appending the ``environ_key`` parameter (
   ``subject_key`` for :py:class:`is_subject` and ``issuer_key`` for
   :py:class:`is_issuer`) with its corresponding X.509 attribute type. For
   example, if ``environ_key`` is ``SSL_CLIENT_S_DN``, and you try to check for
   an organization then the WSGI environment to check will be
   ``SSL_CLIENT_S_DN_O``.
4. There are various rules to determine if the predicate is valid:
    * If the distinguished name has one value for an attribute type, then it
      must equal the value specified in the constructor argument.
    * If the distinguished name has more than one value for the same attribute
      type, and the constructor argument for the predicate is a string (single
      value), then it will be valid if such argument equals at least one of the
      values of the distinguished name. The WSGI environment variables that
      will be checked will follow the same rules as point #3, but suffixed by
      an index number, for example ``SSL_CLIENT_S_DN_O_0``. If there is no such
      variable, then it will follow the rules of point #5.
    * If the distinguished name has more than one value for the same attribute
      type, and the constructor argument is a tuple or a list, then all of the
      values of such argument must be present in the distinguished name.
5. If any of the server variables that are tried are non-existent (with the
   exception of the validity range), then it will try to parse the
   distinguished name, for which the same rules to point #4 will be applied.
6. If there is an error in the parsing, then the predicate will fail.

API
===

.. py:module:: repoze.what.plugins.x509

x509
------------------------
.. autoclass:: repoze.what.plugins.x509.X509Identifier
   :members:

.. py:module:: repoze.what.plugins.x509.predicates

predicates
-----------------------------------
.. autoclass:: repoze.what.plugins.x509.X509Predicate
   :members:
   :special-members:
.. autoclass:: repoze.what.plugins.x509.X509DNPredicate
   :members:
   :special-members:
.. autoclass:: repoze.what.plugins.x509.is_issuer
   :members:
   :special-members:
.. autoclass:: repoze.what.plugins.x509.is_subject
   :members:
   :special-members:

.. py:module:: repoze.what.plugins.x509.utils

utils
-----
.. autofunction:: repoze.what.plugins.x509.utils.parse_dn
.. autofunction:: repoze.what.plugins.x509.utils.verify_certificate
