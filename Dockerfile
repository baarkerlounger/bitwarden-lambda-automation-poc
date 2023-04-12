ARG ARCH="x86_64"
ARG C_LIB="gnu"

FROM public.ecr.aws/lambda/provided:al2 as builder

ARG ARCH
ARG C_LIB

WORKDIR /build
ADD Cargo.toml Cargo.toml
ADD Cargo.lock Cargo.lock
ADD src src

RUN yum install -y gcc unzip openssl openssl-devel pkg-config
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add $ARCH-unknown-linux-${C_LIB} && cargo build --release --target ${ARCH}-unknown-linux-${C_LIB}
RUN curl -LO "https://github.com/bitwarden/clients/releases/download/cli-v2023.3.0/bw-linux-2023.3.0.zip" && unzip *.zip


FROM public.ecr.aws/lambda/provided:al2

ARG ARCH
ARG C_LIB

ENV LAMBDA_TASK_ROOT="/var/task"
WORKDIR ${LAMBDA_TASK_ROOT}
COPY --from=builder /build/target/${ARCH}-unknown-linux-${C_LIB}/release/bitwarden-rs ${LAMBDA_TASK_ROOT}
COPY --from=builder /build/bw ${LAMBDA_TASK_ROOT}
RUN chmod +x ${LAMBDA_TASK_ROOT}/bw

ENTRYPOINT ["./bitwarden-rs"]
