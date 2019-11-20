import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="F1-Fuzzer", # Replace with your own username
    version="0.0.4",
    author="Rahul Gopinath",
    author_email="rahul@gopinath.org",
    description="A fast grammar fuzzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vrthra/f1",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
