#!/usr/bin/env bash
# The Terraform example against a running server, in a copy so the
# example directory stays clean: the apply without the data roles must
# fail on the secret and the blob, the apply with them must succeed,
# and destroy must remove everything. About five minutes: the azurerm
# provider's own pollers, not Provisio.
set -euo pipefail
CI_DIR="${CI_DIR:-/tmp/provisio-ci}"
export SSL_CERT_FILE="$CI_DIR/home/ca.pem"
rm -rf "$CI_DIR/tf" && cp -r examples/terraform "$CI_DIR/tf" && cd "$CI_DIR/tf"
terraform init -input=false >/dev/null
echo "--- apply without the data roles: refused twice"
if terraform apply -input=false -auto-approve \
    -var grant_secrets_officer=false -var grant_blob_contributor=false > apply1.log 2>&1; then
    cat apply1.log; echo "FAIL: the apply without the data roles succeeded" >&2; exit 1
fi
grep -q ForbiddenByRbac apply1.log || { cat apply1.log; echo "FAIL: no 403 on the secret" >&2; exit 1; }
# The provider's first call for the blob is a HEAD (does it exist?), and a
# HEAD carries no body: Terraform reports the bare 403, no error code.
grep -qE 'Blob "hello.txt".*403' apply1.log ||
    { cat apply1.log; echo "FAIL: no 403 on the blob" >&2; exit 1; }
echo "ok  403 on the secret and the blob"
echo "--- apply with the data roles"
terraform apply -input=false -auto-approve > apply2.log 2>&1 ||
    { cat apply2.log; echo "FAIL: the apply with the roles failed" >&2; exit 1; }
grep -q 'blob_url = ' apply2.log || { cat apply2.log; echo "FAIL: no blob_url output" >&2; exit 1; }
echo "ok  $(grep -o 'Resources: .*' apply2.log | tail -1)"
echo "--- destroy"
terraform destroy -input=false -auto-approve > destroy.log 2>&1 ||
    { cat destroy.log; echo "FAIL: destroy failed" >&2; exit 1; }
echo "ok  $(grep -o 'Resources: .*' destroy.log | tail -1)"
echo PASS
