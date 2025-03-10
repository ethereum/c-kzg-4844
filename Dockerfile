FROM gcr.io/oss-fuzz-base/base-builder-rust

# Use nightly
ENV RUSTUP_TOOLCHAIN=nightly

# Install nim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
ENV PATH=/root/.nimble/bin:$PATH

# Clone ckzg
RUN git clone --depth 1 https://github.com/ethereum/c-kzg-4844.git $SRC
