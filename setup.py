from os import chdir, environ
from pathlib import Path
from platform import system
from shutil import which
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from subprocess import check_call


def get_make():
    """Get the GNU make command. Honors $MAKE if set."""
    if "MAKE" in environ:
        return environ["MAKE"]
    if system() == "FreeBSD":
        if not which("gmake"):
            raise RuntimeError("GNU make (gmake) is required on FreeBSD")
        return "gmake"
    return "make"


class CustomBuild(build_ext):
    def run(self):
        if system() == "Windows":
            try:
                check_call(["blst\\build.bat"])
            except Exception:
                pass
        check_call([get_make(), "-C", "src", "blst"])
        super().run()


def main():
    # Change directory so we don't have to deal with paths.
    setup_dir = Path(__file__).parent.resolve()
    chdir(setup_dir)

    setup(
        name="ckzg",
        version="2.1.6",
        author="Ethereum Foundation",
        author_email="security@ethereum.org",
        url="https://github.com/ethereum/c-kzg-4844",
        description="Python bindings for C-KZG-4844",
        long_description=Path("bindings/python/README.md").read_text(),
        long_description_content_type="text/markdown",
        license="Apache-2.0",
        ext_modules=[
            Extension(
                "ckzg",
                sources=["bindings/python/ckzg_wrap.c", "src/ckzg.c"],
                include_dirs=["inc", "src"],
                library_dirs=["lib"],
                libraries=["blst"]
            )
        ],
        cmdclass={
            "build_ext": CustomBuild,
        }
    )


if __name__ == "__main__":
    main()
