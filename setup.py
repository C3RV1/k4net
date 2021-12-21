from setuptools import setup, find_packages

setup(
    name="k4net",
    version="1.0.0",
    author="KeyFr4me",
    description="Network utilities used by KeyFr4me",
    packages=find_packages(include=["k4net"]),
    install_requires=["pycryptodome>=3.9.9"]
)
