import os
import shutil

from setuptools import setup, find_packages, Command

import certbuilder



class CleanCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        folder = os.path.dirname(os.path.abspath(__file__))
        for sub_folder in ['build', 'dist', 'certbuilder.egg-info']:
            full_path = os.path.join(folder, sub_folder)
            if os.path.exists(full_path):
                shutil.rmtree(full_path)


setup(
    name='certbuilder',
    version=certbuilder.__version__,

    description='Creates and signs X509 certificates',
    long_description='Docs for this project are maintained at https://github.com/wbond/certbuilder#readme.',

    url='https://github.com/wbond/certbuilder',

    author='wbond',
    author_email='will@wbond.net',

    license='MIT',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='crypto',

    install_requires=['asn1crypto', 'oscrypto'],
    packages=find_packages(exclude=['tests*', 'dev*']),

    cmdclass={
        'clean': CleanCommand,
    }
)
