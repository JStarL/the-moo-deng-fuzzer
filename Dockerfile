FROM alpine:latest

RUN apk update && apk upgrade && apk add --no-cache \
    python3 \
    py3-virtualenv \
    libc6-compat

RUN mkdir /app

WORKDIR /app

COPY fuzzer.py fuzzer.py
COPY binaries binaries
RUN chmod +x binaries/binaries/*

CMD python3 fuzzer.py
