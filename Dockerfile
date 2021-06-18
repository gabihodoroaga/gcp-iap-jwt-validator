FROM alpine:3.13

WORkDIR /app

ADD bin/iapvalidator .

RUN chmod +x iapvalidator

ENTRYPOINT ["/app/iapvalidator"]
