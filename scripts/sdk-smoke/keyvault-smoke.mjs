// The demo Armite exists for, driven by the real Azure SDK: an Owner
// creates a vault through ARM, cannot read or write a secret in it, grants
// itself Key Vault Secrets Officer, can, and loses the access again the
// moment the assignment is deleted. Exits non-zero on any mismatch.
import {randomUUID} from "node:crypto";
import {ClientSecretCredential} from "@azure/identity";
import {SecretClient} from "@azure/keyvault-secrets";

const ARM = "https://management.localhost:8443";
const SUB = "22222222-2222-2222-2222-222222222222";
const GROUP = "kv-rg";
const VAULT = "kv-demo"; // its hostname must resolve: 127.0.0.1 kv-demo.vault.localhost
const OWNER_OID = "44444444-4444-4444-4444-444444444444";
const SECRETS_OFFICER = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7";
const VAULT_ID = `/subscriptions/${ SUB }/resourceGroups/${ GROUP }`
    + `/providers/Microsoft.KeyVault/vaults/${ VAULT }`;

const cred = new ClientSecretCredential(
    process.env.AZURE_TENANT_ID,
    process.env.AZURE_CLIENT_ID,
    process.env.AZURE_CLIENT_SECRET,
    {disableInstanceDiscovery: true}
);

// arm sends one management-plane request with a fresh ARM token.
async function arm(method, path, body) {
    const tok = await cred.getToken("https://management.azure.com/.default");
    const res = await fetch(ARM + path, {
        method,
        headers: { Authorization: `Bearer ${ tok.token }`, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
}

function ok(cond, what) {
    if (!cond) throw new Error(`FAIL: ${what}`);
    console.log("ok ", what);
}

// refused runs fn and expects a Key Vault error with the given status and
// inner code (the code clients branch on).
async function refused(fn, status, inner, what) {
    try {
        await fn();
    } catch (e) {
        // The SDK deserializes Key Vault's error body into e.details and
        // renames innererror to innerError on the way.
        const got = e.details?.error?.innerError?.code;
        ok(e.statusCode === status && got === inner,
            `${ what } -> ${ e.statusCode } ${ e.code }/${ got }`);
        return;
    }
    throw new Error(`FAIL: ${ what }: succeeded, expected ${ status } ${ inner }`);
}

// 1. Management plane: group and vault, idempotent PUTs.
let r = await arm("PUT", `/subscriptions/${ SUB }/resourcegroups/${ GROUP }?api-version=2024-11-01`,
    { location: "eastus" });
ok(r.status === 200 || r.status === 201, `group ${ GROUP } -> ${ r.status }`);
r = await arm("PUT", `${ VAULT_ID }?api-version=2025-05-01`, {
    location: "eastus",
    properties: {
        tenantId: process.env.AZURE_TENANT_ID,
        sku: { family: "A", name: "standard" },
        enableRbacAuthorization: true,
    },
});

const vaultUri = r.body.properties.vaultUri;
ok(r.status === 200 || r.status === 201, `vault ${ VAULT } -> ${ r.status } ${ vaultUri }`);

// A rerun must start from "no grant": drop whatever the Owner holds here.
const assignments = `${ VAULT_ID }/providers/Microsoft.Authorization/roleAssignments`;
r = await arm("GET", `${ assignments }?api-version=2022-04-01&$filter=atScope()`);
// atScope() also lists inherited assignments (the seeded Owner at the
// subscription), so match the scope too: only the vault's own grants go.
const mine = (a) => a.properties.principalId === OWNER_OID
    && a.properties.scope.toLowerCase() === VAULT_ID.toLowerCase();
for (const a of r.body.value.filter(mine)) {
    await arm("DELETE", `${ a.id }?api-version=2022-04-01`);
    console.log("     dropped a leftover assignment", a.name);
}

// 2. The thesis: Owner of the subscription, nothing on the data plane.
const client = new SecretClient(vaultUri, cred);
await refused(() => client.setSecret("db-pass", "hunter2"), 403, "ForbiddenByRbac",
    "Owner cannot write a secret");
await refused(() => client.getSecret("db-pass"), 403, "ForbiddenByRbac",
    "Owner cannot read a secret");

// 3. Grant Key Vault Secrets Officer at the vault, through ARM.
const assignment = `${ assignments }/${ randomUUID() }`;
r = await arm("PUT", `${ assignment }?api-version=2022-04-01`, {
    properties: {
        roleDefinitionId: `/subscriptions/${ SUB }/providers/Microsoft.Authorization`
            + `/roleDefinitions/${ SECRETS_OFFICER }`,
        principalId: OWNER_OID,
        principalType: "ServicePrincipal",
    },
});
ok(r.status === 201, `grant Key Vault Secrets Officer -> ${ r.status }`);

// 4. The lifecycle the SDK expects, pollers included.
let s = await client.setSecret("db-pass", "hunter2",
    { contentType: "text/plain", tags: { env: "dev" } });
ok(s.value === "hunter2" && s.properties.enabled === true, `setSecret -> ${ s.properties.id }`);
const v1 = s.properties.version;
s = await client.setSecret("db-pass", "hunter3");
ok(s.properties.version !== v1, "second setSecret is a new version");
s = await client.getSecret("db-pass");
ok(s.value === "hunter3", "getSecret returns the current version");
s = await client.getSecret("db-pass", { version: v1 });
ok(s.value === "hunter2", "getSecret by version");
const names = [];
for await (const p of client.listPropertiesOfSecrets()) names.push(p.name);
ok(names.includes("db-pass"), `listPropertiesOfSecrets -> ${ names }`);
let versions = 0;
for await (const _ of client.listPropertiesOfSecretVersions("db-pass")) versions++;
ok(versions === 2, `listPropertiesOfSecretVersions -> ${ versions }`);
let props = await client.updateSecretProperties("db-pass", v1, { enabled: false });
ok(props.enabled === false, "updateSecretProperties disables a version");
await refused(() => client.getSecret("db-pass", { version: v1 }), 403, "SecretDisabled",
    "disabled version cannot be read");
const d = await (await client.beginDeleteSecret("db-pass")).pollUntilDone();
ok(d.properties.recoveryId === `${ vaultUri }deletedsecrets/db-pass`,
    `beginDeleteSecret -> ${ d.properties.recoveryId }`);
await refused(() => client.getSecret("db-pass"), 404, undefined, "deleted secret is not found");
const deleted = [];
for await (const x of client.listDeletedSecrets()) deleted.push(x.name);
ok(deleted.includes("db-pass"), `listDeletedSecrets -> ${ deleted }`);
props = await (await client.beginRecoverDeletedSecret("db-pass")).pollUntilDone();
ok(props.name === "db-pass", "beginRecoverDeletedSecret");
s = await client.getSecret("db-pass");
ok(s.value === "hunter3", "recovered secret reads again");
await (await client.beginDeleteSecret("db-pass")).pollUntilDone();
await client.purgeDeletedSecret("db-pass");
await refused(() => client.getDeletedSecret("db-pass"), 404, undefined, "purged secret is gone");

// 5. Revocation is instant: the provider and the evaluator share one store.
r = await arm("DELETE", `${ assignment }?api-version=2022-04-01`);
ok(r.status === 200 || r.status === 204, `revoke the assignment -> ${ r.status }`);
await refused(() => client.setSecret("db-pass", "again"), 403, "ForbiddenByRbac",
    "Owner cannot write after revocation");

console.log("PASS");

