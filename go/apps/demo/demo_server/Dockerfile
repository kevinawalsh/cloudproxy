FROM scratch
# build_docker.sh copies: demo_server
COPY . /
EXPOSE 8123
ENV TAO_DOMAIN /
WORKDIR .
ENTRYPOINT ["/bin/demo_server", "--logtostderr"]
