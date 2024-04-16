from setuptools import setup, Extension
from pathlib import Path

this_dir = Path(__file__).parent
long_description = (this_dir / "bindings/python/README.md").read_text()


def f(path_str):
    return str(this_dir / path_str)


def main():
    setup(
        name="ckzg",
        version="1.0.0",
        author="Ethereum Foundation",
        author_email="security@ethereum.org",
        url="https://github.com/ethereum/c-kzg-4844",
        description="Python bindings for C-KZG-4844",
        long_description=long_description,
        long_description_content_type="text/markdown",
        license="Apache-2.0",
        ext_modules=[
            Extension(
                "ckzg",
                sources=[f("bindings/python/ckzg.c"), f("src/c_kzg_4844.c")],
                include_dirs=[f("inc"), f("src")],
                library_dirs=[f("lib")],
                libraries=[f("blst")])])


if __name__ == "__main__":
    main()
