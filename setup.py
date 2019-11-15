'''
Standard Python setup script.
'''

from setuptools import setup, find_packages

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='certstream-analytics',
    version='0.1.6',
    description='certstream + analytics',
    url='https://github.com/huydhn/certstream-analytics',
    author='Huy Do',
    author_email='huydhn@gmail.com',
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'elasticsearch_dsl',
        'certstream',
        'pyahocorasick',
        'tldextract',
        'wordsegment',
        'pyenchant',
        'idna',
        'confusable_homoglyphs'
    ],
    tests_require=[
        'coverage',
        'nose',
        'pytest-pep8',
        'pytest-cov',
        'codecov'
    ],
    dependency_links=[
        'https://github.com/casics/nostril/tarball/master'
    ],
    packages=find_packages(),
    scripts=['bin/domain_matching.py'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
