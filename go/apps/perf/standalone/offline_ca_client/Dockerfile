FROM scratch
# build_docker.sh copies: tao_shell
# build_docker.sh copies: linux_host
# build_docker.sh copies: tao_launch
# build_docker.sh copies: offline_ca_client
# build_docker.sh copies domain: /etc/tao-docker-domain-1
COPY . /
ENV TAO_DOMAIN /
WORKDIR .
ENTRYPOINT [ "/bin/tao_shell", \
"/bin/linux_host", "start", "-daemon", "-alsologtostderr", "-verbose", "-v", "4", "-stacked", "-tao_domain", "/etc/tao", ";", \
"sleep", "3s", ";", \
"/bin/tao_launch", "-tao_domain", "/etc/tao", "run", "offline_ca_client" ]
