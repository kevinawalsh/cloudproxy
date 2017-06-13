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

