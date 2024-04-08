from setuptools import setup, find_packages

setup(
    name='cybercrypt',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cyberCrypt=cybercrypt.main:main',
            'cyberCrypt-windows=cybercrypt.main:main',  # For Windows
            'cyberCrypt-linux=cybercrypt.main:main',    # For Linux
            'cyberCrypt-macos=cybercrypt.main:main',    # For macOS
        ],
    },
    install_requires=[
        'pyfiglet',
        'colorama',
        'cryptography',
    ],
    author='El1E-l33t',
    author_email='muhizielie01@gmail.com',
    description='A versatile command-line tool for secure data transformation,hashing operations, and encryption algorithms.',
    url='https://github.com/UwimanaMuhiziElie/cybercrypt.git',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
