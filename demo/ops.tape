# Shot D - operations: the id on an error is the id in the log; kill -9
# and restart, everything is back. The server runs as `armite` on PATH
# with its log in ./armite.log; kv-demo holds db-pass, stdemo holds
# demo/hello.txt and the Owner holds the data roles.
Output ops.mp4
Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 660
Set Padding 20
Set Framerate 24
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "export AZURE_CONFIG_DIR=$DEMO_AZ REQUESTS_CA_BUNDLE=$DEMO_CA PS1='$ '" Enter
Type "clear" Enter
Show

Type `H=$(curl -sS --cacert $REQUESTS_CA_BUNDLE -D - -o /dev/null 'https://management.localhost:8443/subscriptions?api-version=2022-12-01')` Sleep 500ms Enter Sleep 2s
Type `grep -i x-ms- <<<"$H"` Sleep 500ms Enter Sleep 4s
Type `ID=$(awk 'tolower($1)=="x-ms-request-id:"{print $2}' <<<"$H" | tr -d '\r')` Sleep 500ms Enter Sleep 2s
Type "grep $ID armite.log" Sleep 500ms Enter Sleep 6s
Type "kill -9 $(pgrep -x armite)" Sleep 500ms Enter Sleep 2s
Type "armite > armite.log 2>&1 &" Sleep 500ms Enter Sleep 6s
Type "az keyvault secret show --vault-name kv-demo -n db-pass --query value -o tsv" Sleep 500ms Enter Sleep 3s
Type "az storage blob list -c demo --account-name stdemo --auth-mode login --query '[].name' -o tsv" Sleep 500ms Enter Sleep 6s
