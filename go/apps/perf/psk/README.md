Performance Experiment: Pre-shared Key TLS
------------------------------------------

Two tao-hosted processes:
 standalone_psk_client
 standalone_psk_server

Both run on plain linux.
 - both have a hardcoded psk
 - client creates mTLS connection to server, both using the psk
 - client sends 1 byte ping, server responds with 1 byte pong.

All timings taken on client side.

    standalone_psk_server -n 1001
    standalone_psk_client -n 1001

