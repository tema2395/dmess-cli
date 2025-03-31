#!/bin/bash
./p2pd \
  -listen /tmp/p2pd.sock \
  -id keys/private_key.pem \
  -pubkey keys/public_key.pem \
  -loglevel debug
