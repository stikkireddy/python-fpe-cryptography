from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    install_requires = fh.read().splitlines()

setup(
    name="ff3-cryptography",
    author="Sri Tikkireddy",
    author_email="sri.tikkireddy@databricks.com",
    description="Implementation of ff3 based on python-fpe using cryptography instead of pycryptodome.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/stikkireddy/python-fpe-cryptography",
    packages=find_packages(),
    install_requires=install_requires,
    setup_requires=["setuptools_scm"],
    use_scm_version=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
