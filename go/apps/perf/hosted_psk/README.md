Performance Experiment: Pre-shared Key TLS
------------------------------------------

Two tao-hosted processes:
 hosted_psk_client
 hosted_psk_server

These run on tao.
 - both get a shared secret to serve as psk from parent tao
 - client connects to server using mtls psk
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

    export TAO_DOMAIN=/etc/tao-tpm

    # start tao host
    sudo tao host -tao_domain $TAO_DOMAIN start -hosting process

    # make sure there is a domain-signed attestation for tpm
    # tao run tpm_aa -keys /etc/tao-tpm/aa_keys -attestation /etc/tao-tpm/aa-attestation -id 42

    # get the ping/pong subprin names
    rm -f /tmp/*-subprin; for f in hosted_psk_client hosted_psk_server; do tao run $f -show_subprin >/tmp/$f-subprin; done

    # run server
    tao run hosted_psk_server -n 1001 -peer_subprin "`cat /tmp/*-subprin`"

    # run client
    tao run hosted_psk_client -n 1001 -peer_subprin "`cat /tmp/*-subprin`"

For siblings but with client on root linux (A), server on docker (C)

    ./scripts/build_static.sh
    ./scripts/build_docker.sh

    KVM=$(echo -kvm_coreos_img ~/coreos2017/coreos_production_qemu_image.img)
    KEYS=$(echo -kvm_coreos_ssh_auth_keys ~/.ssh/authorized_keys)
    CHILD="process,kvm_coreos,docker,kvm_coreos_linuxhost"
    sudo tao host start -tao_domain $TAO_DOMAIN -hosting $CHILD $KVM $KEYS

    rm -f /tmp/*-subprin
    tao run hosted_psk_client -show_subprin >/tmp/hosted_psk_client-subprin
    tao run docker:/home/kwalsh/src/go/bin/hosted_psk_server.img.tgz -- -show_subprin >/tmp/hosted_psk_server-subprin

    tao run docker:/home/kwalsh/src/go/bin/hosted_psk_server.img.tgz -p 8123:8123 -- -n 1001 -peer_subprin "`cat /tmp/*-subprin`"
    tao run hosted_psk_client -n 1001 -peer_subprin "`cat /tmp/*-subprin`"

For cousins, with client on root linux (A), server on tao-over-kvm-coreos (D)

    see top_to_kvm.sh

For federated

    use -federated flag
