from distutils.core import setup, Extension

def main():
    setup(
        name="ckzg",
        version="1.0.0",
        description="Python interface for C-KZG-4844",
        ext_modules=[
            Extension(
                "ckzg",
                sources=["ckzg.c", "../../src/c_kzg_4844.c"],
                include_dirs=["../../inc", "../../src"],
                library_dirs=["../../lib"],
                libraries=["blst"])])

if __name__ == "__main__":
    main()
