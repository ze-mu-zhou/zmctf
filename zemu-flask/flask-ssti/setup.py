import setuptools
import os

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("VERSION", "r", encoding="utf-8") as f:
    version = f.read().strip()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [
        line.strip() for line in f.readlines()
    ]

setuptools.setup(
    name="fenjing",
    version=version,
    author="Marven11",
    author_email="marven11@example.com",
    description="A Jinja SSTI cracker for CTF competitions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Marven11/Fenjing",
    packages=setuptools.find_packages(),
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'fenjing=fenjing.__main__:main',
        ]
    }
)
