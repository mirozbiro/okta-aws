from setuptools import setup

setup(
    name="okta-aws",
    version="1.0.0",
    description="CLI tool to authenticate to AWS via Okta SAML with MFA support",
    py_modules=["okta_aws"],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.32.0",
        "boto3>=1.34.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
    ],
    entry_points={
        "console_scripts": [
            "assume=okta_aws:main",
            "okta-aws=okta_aws:main",
        ],
    },
)
