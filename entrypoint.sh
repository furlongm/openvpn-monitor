#!/bin/sh
set -e

confd -onetime -backend env --log-level panic 

exec "$@"
