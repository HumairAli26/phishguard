from setuptools import setup, find_packages

setup(
    name="phishguard",
    version="1.0.0",
    description="Phishing Triage & Simulation Toolkit — DecodeLabs Project 3",
    author="Humair",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "matplotlib>=3.7",
        "numpy>=1.24",
        "reportlab>=4.0",
        "colorama>=0.4.6",
        "validators>=0.22",
        "python-dateutil>=2.8",
    ],
    entry_points={
        "console_scripts": [
            "phishguard=phishguard.main:main",
        ],
    },
    python_requires=">=3.9",
)
