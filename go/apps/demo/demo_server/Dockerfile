FROM scratch
COPY . /
EXPOSE 8123
ENV TAO_DOMAIN /
WORKDIR .
ENTRYPOINT ["/bin/demo_server", "--logtostderr"]
