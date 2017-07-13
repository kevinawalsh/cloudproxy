FROM scratch
# build_docker.sh copies: tao_shell
# build_docker.sh copies: linux_host
# build_docker.sh copies: tao_launch
# build_docker.sh copies: standalone_ca_server
# build_docker.sh copies domain: /etc/tao-docker-domain-1
COPY . /
EXPOSE 8123
ENV TAO_DOMAIN /
WORKDIR .
ENTRYPOINT [ "/bin/tao_shell", \
"/bin/linux_host", "start", "-daemon", "-alsologtostderr", "-verbose", "-v", "4", "-stacked", "-tao_domain", "/etc/tao", ";", \
"sleep", "3s", ";", \
"/bin/tao_launch", "-tao_domain", "/etc/tao", "run", "standalone_ca_server" ]
