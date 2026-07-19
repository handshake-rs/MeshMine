#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/tla2tools.jar" >&2
  exit 2
fi

jar=$1
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 1 \
  -config models/mask-session.cfg models/mask_session.tla
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 1 \
  -config models/receipt-close.cfg models/receipt_close.tla
java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers 1 \
  -config models/payout-snapshot.cfg models/payout_snapshot.tla
