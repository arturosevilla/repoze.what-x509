# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
readme = open(os.path.join(here, 'README')).read()
version = open(os.path.join(here, 'VERSION')).readline().strip()

setup(name='repoze.what.plugins.x509',
      version=version,
      description='x509 repoze.what plugin',
      long_description=readme,
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Environment :: Web Environment',
          'License :: OSI Approved :: BSD License',
          'Intended Audience :: Developers',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Security'
      ],
      keywords='web x509 repoze what authentication client certificate',
      author='Arturo Sevilla',
      author_email='arturo@ckluster.com',
      namespace_packages=['repoze', 'repoze.what', 'repoze.what.plugins'],
      url='http://www.ckluster.com/',
      license='Modified BSD License (http://www.ckluster.com/OPEN_LICENSE.txt',
      packages=find_packages(exclude=['*.tests', '*.tests.*', 'tests.*',
                                      'tests']),
      include_package_data=True,
      zip_safe=True,
      tests_require=[
          'repoze.who >= 1.0.14,<2.0',
          'repoze.what >= 1.0.9,<2.0',
          'python-dateutil < 2.0',
          'coverage',
          'pyasn1 >= 0.1.2',
          'nose'
      ],
      install_requires=[
          'repoze.who >= 1.0.14,<2.0',
          'repoze.what >= 1.0.9,<2.0',
          'python-dateutil < 2.0',
          'pyasn1 >= 0.1.2'
      ],
      test_suite='nose.collector',
      entry_points=''
)
