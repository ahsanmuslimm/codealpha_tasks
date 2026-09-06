"""Setup configuration for NetSentry."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="netsentry",
    version="1.0.0",
    author="Muhammad Ahsan",
    description="Professional Network Packet Sniffer for Cybersecurity Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/netsentry",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    entry_points={
        "console_scripts": [
            "netsentry=netsentry.cli:main",
        ],
    },
)
