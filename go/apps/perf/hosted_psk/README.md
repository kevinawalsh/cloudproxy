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

