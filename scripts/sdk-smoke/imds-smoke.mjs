import { ManagedIdentityCredential } from "@azure/identity";

// No tenant, client id or secret: the platform is the credential. Locally the
// "platform" is Armite's IMDS listener, reached via AZURE_POD_IDENTITY_AUTHORITY_HOST.
const cred = new ManagedIdentityCredential();

const tok = await cred.getToken("https://management.azure.com/.default");
const payload = tok.token.split(".")[1];
console.log(JSON.stringify(JSON.parse(Buffer.from(payload, "base64url")), null, 2));
console.log("expiresOnTimestamp (ms):", tok.expiresOnTimestamp, "-->", new Date(tok.expiresOnTimestamp).toISOString());

const tok2 = await cred.getToken("https://management.azure.com/.default");
console.log("cached: ", tok2.token === tok.token);
