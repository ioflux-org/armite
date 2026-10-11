# Shot E - Docker: the published image, Azurite inside, nothing to
# install. The host server is stopped; the image is pulled already;
# az is registered against 8443 in $DEMO_AZ_DOCKER.
Output docker.mp4
Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 660
Set Padding 20
Set Framerate 24
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "export AZURE_CONFIG_DIR=$DEMO_AZ_DOCKER PS1='$ '" Enter
Type "clear" Enter
Show

Type "docker run -d --name armite -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \" Enter
Type "  -v armite:/data ghcr.io/ioflux-org/armite" Sleep 500ms Enter Sleep 7s
Type "docker logs armite" Sleep 500ms Enter Sleep 7s
Type "docker cp armite:/data/ca.pem ./ca.pem" Sleep 500ms Enter Sleep 2s
Hide
Type "export REQUESTS_CA_BUNDLE=$PWD/ca.pem; az cloud register -n Armite --endpoint-resource-manager https://management.localhost:8443 && az cloud set -n Armite && az config set core.instance_discovery=false core.only_show_errors=true" Enter
Sleep 6s
Type "az login --service-principal -u 33333333-3333-3333-3333-333333333333 -p armite-secret --tenant 11111111-1111-1111-1111-111111111111 -o none && az account show --query name -o tsv" Enter
Sleep 6s
Type "clear" Enter
Show
Type "REQUESTS_CA_BUNDLE=./ca.pem az group create -n docker-rg -l eastus --query name -o tsv" Sleep 500ms Enter Sleep 4s
Type "docker exec armite /app/armite hosts" Sleep 500ms Enter Sleep 6s
