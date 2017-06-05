Performance Experiment: Standalone Proccess
-------------------------------------------

Two processes:
 standalone_client
 standalone_server

These run on plain linux. They each:
 - pick a random key
 - contact a CA to get an x509 cert signed by root key
 - client creates mTLS connection to server
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

