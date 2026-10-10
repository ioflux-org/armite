#!/usr/bin/env bash
# Prints the /etc/hosts lines the smoke scripts need: the fixed names
# and the vault and storage account they create. On a machine whose
# resolver already answers *.localhost (Linux with systemd-resolved)
# this is harmless; elsewhere: ./scripts/ci/hosts.sh | sudo tee -a /etc/hosts
for name in management.localhost login.localhost kv-demo.vault.localhost \
    stdemo.blob.core.localhost stdemo.queue.core.localhost stdemo.table.core.localhost; do
    echo "127.0.0.1  $name"
done
