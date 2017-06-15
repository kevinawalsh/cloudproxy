Performance Experiment: Centralized Attestation Authority
---------------------------------------------------------

Two tao-hosted processes:
 centralized_client
 centralized_server
Two third-party servers:
 tpm_aa (offline)
 app_ca (online)

The tpm aa runs on plain linux. The client, server, and app ca all run on tao.
 - tpm aa has a root key
 - tpm aa signs attestation for each tpm, offline
 - client and server pick a random key
 - client and server gets attestation from tao host, all the way up to tpm
 - client and server contact app aa (using approach in ../attestation/) to get 
   new signed x509 certs for ther existing ephemeral keys, signed by the
   app ca's key
 - client creates mTLS connection to server, both using the app ca signed certs
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

    export TAO_DOMAIN=/etc/tao-tpm

    # start tao host
    sudo tao host -tao_domain $TAO_DOMAIN start -hosting process

    # make sure there is a domain-signed attestation for tpm
    tao run tpm_aa -keys /etc/tao-tpm/aa_keys -attestation /etc/tao-tpm/aa-attestation -id 42

    # get the ping/pong/app_ca subprin names
    rm -f /tmp/*-subprin; for f in app_ca centralized_client centralized_server; do tao run $f -show_subprin >/tmp/$f-subprin; done

    # run app ca
    tao run app_ca -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

    # run server
    tao run centralized_server -n 1001 -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

    # run client
    tao run centralized_client -n 1001 -local_tpm_attestation /etc/tao-tpm/aa-attestation -peer_subprin "`cat /tmp/*-subprin`"

