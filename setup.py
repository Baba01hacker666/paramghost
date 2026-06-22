from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="paramghost",
    version="2.0.0",  # Initial PyPI version
    author="baba01hacker",
    description="Advanced parameter discovery and fuzzing tool via JS source analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Baba01hacker666/paramghost",
    packages=find_packages(),
    py_modules=["paramghost"],
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "paramghost=paramghost:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
)
