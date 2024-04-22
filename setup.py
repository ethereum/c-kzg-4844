from pathlib import Path
from platform import system
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from subprocess import check_call

this_dir = Path(__file__).parent
long_description = (this_dir / "bindings/python/README.md").read_text()


def r(path_str):
    """
    For a given path, get the relative path the current working directory.
    The result will be a string, rather than a Path object.
    """
    absolute_path = this_dir / path_str
    relative_path = absolute_path.relative_to(Path.cwd())
    return str(relative_path)


class CustomBuild(build_ext):
    def run(self):
        if system() == "Windows":
            try:
                check_call([r("blst\\build.bat")])
            except Exception:
                pass
        check_call(["make", "-C", r("src"), "blst"])
        super().run()


def main():
    setup(
        name="ckzg",
        version="1.0.1",
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
                sources=[r("bindings/python/ckzg.c"), r("src/c_kzg_4844.c")],
                include_dirs=[r("inc"), r("src")],
                library_dirs=[r("lib")],
                libraries=["blst"]
            )
        ],
        cmdclass={
            "build_ext": CustomBuild,
        }
    )


if __name__ == "__main__":
    main()
