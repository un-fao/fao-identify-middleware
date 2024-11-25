from setuptools import setup, find_packages

setup(
    name="fao-identify-middleware",
    version="0.1.0",
    description="Identify Middleware for FastAPI Applications",
    author="Martial Wafo",
    author_email="martial.wafo@fao.org",
    packages=find_packages(),
    install_requires=[
        "fastapi==0.115.5",
        "google-auth==2.36.0",
        "httpx==0.27.2"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
