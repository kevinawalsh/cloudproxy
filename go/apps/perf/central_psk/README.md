Performance Experiment: Pre-shared Key TLS
------------------------------------------

Three tao-hosted processes:
 attested_psk_client
 attested_psk_server
Two third-party servers:
 tpm_aa (offline)
 psk_ka (online)

The tpm aa runs on plain linux. The rest run on tao.
 - psk_ka generates a random generating key
 - server and client contact psk_ka to get a psk
 - client connects to server using mtls psk
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

    export TAO_DOMAIN=/etc/tao-tpm

    # start tao host
    sudo tao host -tao_domain $TAO_DOMAIN start -hosting process

    # make sure there is a domain-signed attestation for tpm
    tao run tpm_aa -keys /etc/tao-tpm/aa_keys -attestation /etc/tao-tpm/aa-attestation -id 42

    # get the ping/pong/app_ca subprin names
    rm -f /tmp/*-subprin; for f in psk_ka attested_psk_client attested_psk_server; do tao run $f -show_subprin >/tmp/$f-subprin; done

    # run app ca
    tao run psk_ka -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

    # run server
    tao run attested_psk_server -n 1001 -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

    # run client
    tao run attested_psk_client -n 1001 -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

