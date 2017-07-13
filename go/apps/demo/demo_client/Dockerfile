FROM scratch
# build_docker.sh copies: demo_client
COPY . /
ENV TAO_DOMAIN /
WORKDIR .
ENTRYPOINT ["/bin/demo_client", "--logtostderr"]
