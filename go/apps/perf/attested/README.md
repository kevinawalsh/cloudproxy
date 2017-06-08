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

