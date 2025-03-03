from setuptools import setup, find_packages

setup(
    name="lib_vale",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pymysql",
        "boto3"
    ],
    python_requires=">=3.6",
)
