#build stage
FROM golang:alpine AS build-env
ADD . /go/src/cortex-proxy
WORKDIR /go/src/cortex-proxy
RUN ls && apk add git && go get -u github.com/golang/dep/cmd/dep && dep ensure && go build -o cortex-proxy

# final stage
FROM alpine
WORKDIR /app
COPY --from=build-env /go/src/cortex-proxy/cortex-proxy /app/

ENTRYPOINT ["./cortex-proxy"]
EXPOSE 8070