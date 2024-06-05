import pathlib
from setuptools import setup

HERE = pathlib.Path(__file__).parent

README = (HERE /"README.md").read_text()
setup(
    name="cryepto",
    version="1.0.0",
    description="cryepto is a simple cryptographic library that provides cryptographic and algorithms so simple.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/georgecane/cryepto",
    author="George Cane",
    author_email="zenwhats@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
    ],
    packages=["cryepto"],
    include_package_data=True,

)