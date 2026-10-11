# Shot A - "Owner can't read the secret". The server is running, az is
# logged in as the built-in Owner, kv-rg and kv-demo exist; nothing is
# granted on the vault yet. Renders the README GIF and an MP4.
Output hero.mp4
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

Type "az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2"
Sleep 600ms
Enter
Sleep 5s

Type "az role assignment create --role 'Key Vault Secrets Officer' \"
Enter
Type "  --assignee-object-id 44444444-4444-4444-4444-444444444444 \"
Enter
Type "  --assignee-principal-type ServicePrincipal \"
Enter
Type "  --scope $(az keyvault show -n kv-demo -g kv-rg --query id -o tsv) -o none"
Sleep 600ms
Enter
Sleep 3s

Type "az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2 --query name -o tsv"
Sleep 600ms
Enter
Sleep 2s

Type "az keyvault secret show --vault-name kv-demo -n db-pass --query value -o tsv"
Sleep 600ms
Enter
Sleep 5s
