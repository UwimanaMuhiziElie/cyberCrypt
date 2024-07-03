from setuptools import setup, find_packages

setup(
    name='cybercrypt',
    version='1.0.1',
    packages=find_packages(include=['core', 'core.*']),
    entry_points={
        'console_scripts': [
            'cyberCrypt=cybercrypt:main',
            'cyberCrypt-windows=cybercrypt:main',  
            'cyberCrypt-linux=cybercrypt:main',   
        ],
    },
    install_requires=[
        'pyfiglet',
        'colorama',
        'cryptography',
        'pytest-asyncio',  
        'aiofiles',
        'bcrypt',       
    ],
    extras_require={
        'dev': [
            'pytest',
            'pytest-asyncio',
        ],
    },
    author='El13',
    author_email='muhizielie01@gmail.com',
    description='A versatile command-line tool for secure data transformation, hashing operations, and encryption algorithms.',
    url='https://github.com/UwimanaMuhiziElie/cybercrypt.git',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
