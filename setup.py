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
        built = False
        if system() == "Windows":
            try:
                print("Check if MSVC is installed")
                check_call(["cl.exe"])
                print("MSVC is installed")
                check_call([f("blst\\build.bat")])
                print("a")
                check_call(["move", f("blst\\build\\blst.lib"), f("lib")])
                print("b")
                check_call(["move", f("blst\\bindings\\*.h"), f("inc")])
                print("c")
                built = True
            except Exception:
                pass

        if not built:
            check_call(["make", "-C", f("src"), "c_kzg_4844.o"])
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
