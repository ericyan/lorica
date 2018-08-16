FROM golang:1.10.4-stretch as builder

# Install libltdl-dev (required by pkcs11)
RUN set -x \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libltdl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . $GOPATH/src/github.com/ericyan/lorica/
WORKDIR $GOPATH/src/github.com/ericyan/lorica/

RUN set -x \
 && go get -v -d ./... \
 && go install -ldflags "-linkmode external -extldflags -static" ./cmd/lorica

FROM gcr.io/distroless/base

COPY --from=builder /go/bin/lorica /
ENTRYPOINT ["/lorica"]
