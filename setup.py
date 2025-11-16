from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="artemis-threat-hunting",
    version="1.0.0",
    author="Artemis Development Team",
    author_email="artemis@example.com",
    description="Hierarchical threat hunting system with meta-learning coordination",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/artemis",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.20.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ]
    },
    entry_points={
        "console_scripts": [
            "artemis=artemis.cli:main",
        ],
    },
)
