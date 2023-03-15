import pathlib
from setuptools import setup, find_packages

here = pathlib.Path(__file__).parent.resolve()
#long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="vppcounters",
    version="0.0.1",
    description="Generating counters for the VPP stats segment",
#    long_description=long_description,
#    long_description_content_type="text/markdown",
    author="O. Troan",
    author_email="otroan@employees.org",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["pydantic", "typer"],
    entry_points={
        "console_scripts": [
            ['vppcounters=counters:app']
        ],
    },
)

