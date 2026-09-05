import { ClientSecretCredential } from "@azure/identity";

const cred = new ClientSecretCredential(
    process.env.AZURE_TENANT_ID,
    process.env.AZURE_CLIENT_ID,
    process.env.AZURE_CLIENT_SECRET,
    { disableInstanceDiscovery: true },
);

const tok = await cred.getToken("https://management.azure.com/.default");
console.log("Token: ", JSON.stringify(cred, null, 2));
const res = await fetch(
    "https://management.localhost:8443/subscriptions?api-version=2022-12-01",
    {
        headers: {
            Authorization: `Bearer ${ tok.token }`
        }
    }
);

console.log(res.status, res.headers.get("x-ms-error-code"));
console.log(await res.text());
