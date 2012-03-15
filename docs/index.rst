
**********************************
The :mod:`repoze.what` X509 plugin
**********************************

:Author: `Arturo Sevilla <http://www.ckluster.com/>`_.
:Latest release: |release|

.. module:: repoze.what.plugins.x509
.. moduleauthor:: Arturo Sevilla <arturo@ckluster.com>

.. topic:: Overview

    This plugin enables :mod:`repoze.what` to check authorization according to
    SSL client certificates. It can check the fields (attribute types) in
    either the subject or issuer distinguished name.

    It supports "out of the box" ``mod_ssl`` if ``mod_wsgi`` is also activated
    in Apache, and Nginx SSL functionality. However, this documentation also
    includes configuration examples for both Apache and Nginx for when both are
    working as reverse proxies.

    This plugin was developed independently of the repoze project (copyrighted
    to Agendaless Consulting, Inc.).

Installing this plugin
======================

The minimum requirements for installation are :mod:`repoze.what`,
:mod:`repoze.who`, and ``python-dateutil``. If you want to run the tests, then
Nose and its coverage plugin will also be installed. It can be installed with
``easy_install``::
    
    easy_install repoze.what-x509

Support and development
=======================

The project is hosted on `GitHub
<https://github.com/arturosevilla/repoze.what-x509/>`_.

Quick setup
===========

In order to protect a resource you must create the corresponding predicate
according to what conditions you need to fulfill.

There are two base predicate classes: :py:class:`X509Predicate` and
:py:class:`X509DNPredicate`, however you will mostly be using the two derived
predicates:

* :py:class:`is_issuer`: This predicate enables you to establish conditions and
  authorize based on the issuer of the certificate.
* :py:class:`is_subject`: This predicate enables you to establish conditions and
  authorize based on the subject of the certificate.

The issuer and the subject are SSL terms corresponding who issued the
certificate, and to whom.

For example, if you want to protect a resource when the issuer of the
certificate is "XYZ Company", then you create it as follows::

    from repoze.what.plugins.x509 import is_issuer

    predicate = is_issuer(organization='XYZ Company')

If you want to allow access only to the user named "John Smith" then you create
the predicate as follows::
    
    from repoze.what.plugins.x509 import is_subject

    predicate = is_subject(common_name='John Smith')

Then you can evaluate these predicates according to your system, for example if
you are using pylons and the :mod:`repoze.what.plugins.pylonshq` plugin then
you could use ``ActionProtector`` or ``ControllerProtector`` with the created
predicates.

You will need to setup Apache or Nginx (or any other server) to work with SSL
client certificates. See :doc:`configuration` for examples.

If you want to use the ``IIdentifier`` object, then you can build it as
follows, and the pass it to the ``identifiers`` parameter of
``repoze.who.middleware.PluggableAuthenticationMiddleware``::
    
    from repoze.what.plugins.x509 import X509Identifier

    identifer = X509Identifier('SSL_CLIENT_S_DN')

The required parameter of :py:class:`X509Identifier` is the WSGI environment
key of the "distinguished name" of the client certificate subject. By default
the credentials are based on the "Email" field, but it can be customized as
follows::

    from repoze.what.plugis.x509 import X509Identifier

    identifier = X509Identifier('SSL_CLIENT_S_DN', login_field='CN')

In this case it will try to get the credentials from the common name of the
client certificate subject.

Contents
========

.. toctree::
   :maxdepth: 2

   changes
   configuration

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

