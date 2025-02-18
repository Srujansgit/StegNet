from setuptools import setup, find_packages

setup(
    name="stegnet",
    version="0.1.0",
    author="Abhigyan Tripathi, Chilveri Srujan Kumar",
    description="A network steganography toolkit for covert communication over TCP, ICMP, DNS, and HTTP.",
    long_description=open("docs/README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Srujansgit/StegNet",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "flask",
        "requests",
        "scapy",
        "typer",
    ],
    entry_points={
        "console_scripts": [
            "stegnet=stegnet.cli:app",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
