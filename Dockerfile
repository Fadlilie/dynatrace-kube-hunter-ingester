FROM scratch

COPY ./app /
COPY ./build/root-ca.cert /etc/ssl/certs/
ENTRYPOINT ["/app"]