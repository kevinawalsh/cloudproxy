Performance Experiment: Standalone Proccess, insecure
-----------------------------------------------------

Two processes:
 standalone_client
 standalone_server

These run on plain linux. They each:
 - client creates TCP connection to server
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.


     standalone_server -n 1001
     standalone_client -n 1001


Performance Experiment: Standalone Proccess, with mTLS and CA
-------------------------------------------------------------

Two processes:
 standalone_ca_client
 standalone_ca_server
One third-party server:
 standalone_ca

These all run on plain linux.
 - ca has a root key and cert (or maybe subsidiary key and chain of certs)
 - client and server pick a random key
 - client and server contact ca to get an x509 cert
 - client creates mTLS connection to server, validate peer using same root
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

     standalone_ca
     standalone_ca_server -n 1001
     standalone_ca_client -n 1001
     offline_ca_client -n 1001
