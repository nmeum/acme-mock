FROM golang:1.21.6-alpine

RUN mkdir -p /usr/src/acme-mock
WORKDIR /usr/src/acme-mock

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod .
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/go/bin ./...

# Create certificate
RUN apk add openssl && \
    yes "" | openssl req -x509 -nodes -newkey rsa:4096 \
	-keyout key.pem -out cert.pem

CMD ["acme-mock", "-a", ":443", "-b", "4096", "-c", "cert.pem", "-k", "key.pem"]

EXPOSE 443
