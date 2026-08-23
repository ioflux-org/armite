import { ClientSecretCredential } from "@azure/identity";

const cred = new ClientSecretCredential(
    process.env.AZURE_TENANT_ID,
    process.env.AZURE_CLIENT_ID,
    process.env.AZURE_CLIENT_SECRET,
    // Provisio's host isn't on MSAL's well-known list; without this MSAL asks
    // login.microsoftonline.com to vouch for it and gets invalid_instance.
    {disableInstanceDiscovery: true}
)

const tok = await cred.getToken("https://management.azure.com/.default");
const payload = tok.token.split(".")[1];
console.log(JSON.stringify(JSON.parse(Buffer.from(payload, "base64url")), null, 2));
console.log("expiresOnTimestamp (ms):", tok.expiresOnTimestamp, "-->", new Date(tok.expiresOnTimestamp).toISOString());

const tok2 = await cred.getToken("https://management.azure.com/.default");
console.log("cached: ", tok2.token === tok.token);
