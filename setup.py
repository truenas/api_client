from setuptools import find_packages, setup


setup(
    name="truenas_api_client",
    description="TrueNAS API client",
    packages=find_packages(),
    license="LGPLv3",
    install_requires=[
        "websocket-client",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "midclt = truenas_api_client:main",
        ],
    },
)
