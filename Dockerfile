# Use the rust builder
FROM gcr.io/oss-fuzz-base/base-builder-rust

# Use nightly
ENV RUSTUP_TOOLCHAIN=nightly

# Set necessary linking flags
ENV RUSTFLAGS="-C link-args=-lc++ -C link-args=-lc++abi"

# Install nim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
ENV PATH=/root/.nimble/bin:$PATH

# Clone the c-kzg-4844 repository
RUN git clone --recursive --depth=1 https://github.com/ethereum/c-kzg-4844.git

# Set our build script as the entry point
ENTRYPOINT "c-kzg-4844/build.sh"
