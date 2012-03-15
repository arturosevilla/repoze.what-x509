
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


Contents
========

.. toctree::
   :maxdepth: 2



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

