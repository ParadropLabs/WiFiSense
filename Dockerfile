FROM golang:1.7

COPY main.go /opt/sensing/
WORKDIR /opt/sensing

RUN apt-get update && \
    apt-get install -y libpcap-dev && \
    go get -d -v && \
    go build

CMD ["./sensing"]
