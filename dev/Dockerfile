FROM alpine:3.9 
RUN apk add ca-certificates

COPY ./build/app /app

CMD ["/app"]
EXPOSE 8080