# Shot B - storage: the Owner creates the container and cannot upload
# the blob; a data role fixes it; a user delegation SAS reads the blob
# and dies the moment the role is revoked. Server running on a fresh
# state with Azurite, az logged in as the built-in Owner.
Output storage.mp4
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

Type "az group create -n st-rg -l eastus -o none" Sleep 500ms Enter Sleep 2s
Type "az storage account create -n stdemo -g st-rg -l eastus --sku Standard_LRS -o none" Sleep 500ms Enter Sleep 5s
Type "az storage container create -n demo --account-name stdemo --auth-mode login -o none" Sleep 500ms Enter Sleep 2s
Type "echo hello > hello.txt" Sleep 300ms Enter Sleep 500ms
Type "az storage blob upload -f hello.txt -c demo -n hello.txt --account-name stdemo --auth-mode login" Sleep 500ms Enter Sleep 6s
Type "az role assignment create --role 'Storage Blob Data Contributor' \" Enter
Type "  --assignee-object-id 44444444-4444-4444-4444-444444444444 \" Enter
Type "  --assignee-principal-type ServicePrincipal \" Enter
Type "  --scope $(az storage account show -n stdemo -g st-rg --query id -o tsv) -o none" Sleep 500ms Enter Sleep 3s
Type "az storage blob upload -f hello.txt -c demo -n hello.txt --account-name stdemo --auth-mode login --no-progress -o none" Sleep 500ms Enter Sleep 3s
Type "SAS=$(az storage blob generate-sas -c demo -n hello.txt --account-name stdemo --permissions r \" Enter
Type "  --expiry $(date -u -d '+1 day' +%Y-%m-%dT%H:%MZ) --auth-mode login --as-user -o tsv)" Sleep 500ms Enter Sleep 3s
Type "BLOB=$(az storage account show -n stdemo -g st-rg --query primaryEndpoints.blob -o tsv)" Sleep 500ms Enter Sleep 2s
Type `curl -s --cacert $REQUESTS_CA_BUNDLE "${BLOB}demo/hello.txt?$SAS"` Sleep 500ms Enter Sleep 3s
Type "az role assignment delete --assignee 44444444-4444-4444-4444-444444444444 \" Enter
Type "  --role 'Storage Blob Data Contributor' \" Enter
Type "  --scope $(az storage account show -n stdemo -g st-rg --query id -o tsv)" Sleep 500ms Enter Sleep 3s
Type `curl -s --cacert $REQUESTS_CA_BUNDLE "${BLOB}demo/hello.txt?$SAS"; echo` Sleep 500ms Enter Sleep 6s
