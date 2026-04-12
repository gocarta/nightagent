from setuptools import setup
from os import path

this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, "README.md")) as f:
    long_description = f.read()

setup(
    name="nightagent",
    packages=["nightagent"],
    package_dir={"nightagent": "nightagent"},
    package_data={
        "nightagent": [
            "__init__.py",
        ]
    },
    entry_points={
        'console_scripts': ['nightagent=nightagent.__init__:main'],
    },    
    version="0.6.0",
    description="Automatically Detect and Repair Common Firewall Issues",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Daniel J. Dufour",
    author_email="daniel.j.dufour@gmail.com",
    url="https://github.com/gocarta/nightagent",
    download_url="https://github.com/gocarta/nightagent/tarball/download",
    keywords=["data", "python"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "netmiko",
    ],
)