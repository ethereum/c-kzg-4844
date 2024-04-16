from pathlib import Path
from platform import system
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from subprocess import check_call

this_dir = Path(__file__).parent
long_description = (this_dir / "bindings/python/README.md").read_text()


def f(path_str):
    return str(this_dir / path_str)


class CustomBuild(build_ext):
    def run(self):
        try:
            # Try to build things the normal way first.
            check_call(["make", "-C", f("src"), "c_kzg_4844.o"])
            super().run()
            return
        except Exception:
            # If we're on Windows, try the weird way.
            if system() == "Windows":
                # This will fail if MSVC is not installed
                check_call(["cl.exe"])
                check_call([f("blst\\build.bat")])
                try:
                    check_call(["move", f("blst\\build\\blst.lib"), f("lib")])
                except Exception:
                    raise Exception("failed to move blst.lib")
                try:
                    check_call(["move", f("blst\\bindings\\blst.h"), f("inc")])
                    check_call(["move", f("blst\\bindings\\blst_aux.h"), f("inc")])
                except Exception:
                    raise Exception("failed to move header files")
                super().run()
                return
            else:
                raise


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
                sources=[f("bindings/python/ckzg.c"), f("src/c_kzg_4844.c")],
                include_dirs=[f("inc"), f("src")],
                library_dirs=[f("lib")],
                libraries=["blst"]
            )
        ],
        cmdclass={
            "build_ext": CustomBuild,
        }
    )


if __name__ == "__main__":
    main()
