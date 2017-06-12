Performance Experiment: Attested Proccess
-----------------------------------------

Two tao-hosted processes:
 attested_client
 attested_server
One third-party server:
 tpm_aa (offline)

The tpm_aa runs on plain linux. The client and server run on tao.
 - aa has a root key
 - aa signs attestation for each tpm, offline
 - client and server pick a random key
 - client and server gets attestation from tao host, all the way up to tpm
 - client creates mTLS connection to server, both using self-signed certs
 - then trade attestations
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

    # start tao host
    sudo tao host start -tao_domain /etc/tao-tpm -hosting process

    # make sure there is a domain-signed attestation for tpm
    tao -tao_domain /etc/tao-tpm run tpm_aa -keys /etc/tao-tpm/aa_keys -attestation /etc/tao-tpm/aa-attestation -id 42

    # get the ping/pong subprin names
    sudo tao -tao_domain /etc/tao-tpm run attested_client -show_subprin >/tmp/client-subprin
    sudo tao -tao_domain /etc/tao-tpm run attested_server -show_subprin >/tmp/server-subprin

    # run server
    tao -tao_domain /etc/tao-tpm run attested_server -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin `cat /tmp/client-subprin`

    # run client
    sudo tao -tao_domain /etc/tao-tpm run attested_client -n 1 -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin `cat /tmp/server-subprin`


