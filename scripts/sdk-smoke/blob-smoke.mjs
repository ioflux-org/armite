// The storage demo, driven by the real Azure SDK: an Owner creates a
// storage account and a container through ARM, cannot upload a blob
// (container operations are management actions, blob operations are
// data actions - Azure's own split), grants itself Storage Blob Data
// Contributor, can, uses the account key and a service SAS (validated by
// Azurite), then a user delegation SAS (issued and validated by
// Armite) - which stops working the moment the grant is revoked.
// Exits non-zero on any mismatch.
import {randomUUID} from "node:crypto";
import {ClientSecretCredential} from "@azure/identity";
import {BlobServiceClient, StorageSharedKeyCredential, BlobSASPermissions,
    generateBlobSASQueryParameters} from "@azure/storage-blob";

const ARM = process.env.ARMITE_ARM ?? "https://management.localhost:8443";
const SUFFIX = process.env.ARMITE_STORAGE_SUFFIX ?? "core.localhost:8443";
const SUB = "22222222-2222-2222-2222-222222222222";
const GROUP = "st-rg";
const ACCOUNT = "stdemo"; // its hostname must resolve: stdemo.blob.core.localhost
const CONTAINER = "demo";
const OWNER_OID = "44444444-4444-4444-4444-444444444444";
const BLOB_DATA_CONTRIBUTOR = "ba92f5b4-2d11-453d-a403-e96b0029c9fe";
const ACCOUNT_ID = `/subscriptions/${ SUB }/resourceGroups/${ GROUP }`
    + `/providers/Microsoft.Storage/storageAccounts/${ ACCOUNT }`;
const BLOB_URL = `https://${ ACCOUNT }.blob.${ SUFFIX }`;

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

// refused runs fn and expects a storage error with the given status and
// x-ms-error-code (the code clients branch on).
async function refused(fn, status, code, what) {
    try {
        await fn();
    } catch (e) {
        const got = e.details?.errorCode ?? e.code;
        ok(e.statusCode === status && got === code, `${ what } -> ${ e.statusCode } ${ got }`);
        return;
    }
    throw new Error(`FAIL: ${ what }: succeeded, expected ${ status } ${ code }`);
}

// 1. Management plane: group and account, idempotent PUTs.
let r = await arm("PUT", `/subscriptions/${ SUB }/resourcegroups/${ GROUP }?api-version=2024-11-01`,
    { location: "eastus" });
ok(r.status === 200 || r.status === 201, `group ${ GROUP } -> ${ r.status }`);
r = await arm("PUT", `${ ACCOUNT_ID }?api-version=2025-08-01`,
    { location: "eastus", sku: { name: "Standard_LRS" }, kind: "StorageV2",
        properties: { allowSharedKeyAccess: true } });
ok(r.status === 200, `storage account ${ ACCOUNT } -> ${ r.status } ${ r.body.properties.primaryEndpoints.blob }`);

// A rerun must start from "no grant": drop whatever the Owner holds here.
const assignments = `${ ACCOUNT_ID }/providers/Microsoft.Authorization/roleAssignments`;
r = await arm("GET", `${ assignments }?api-version=2022-04-01&$filter=atScope()`);
const mine = (a) => a.properties.principalId === OWNER_OID
    && a.properties.scope.toLowerCase() === ACCOUNT_ID.toLowerCase();
for (const a of r.body.value.filter(mine)) {
    await arm("DELETE", `${ a.id }?api-version=2022-04-01`);
    console.log("     dropped a leftover assignment", a.name);
}

// 2. The thesis: Owner may create a container (a management action) and
// may not touch a blob (data actions).
const service = new BlobServiceClient(BLOB_URL, cred);
const container = service.getContainerClient(CONTAINER);
await container.createIfNotExists();
ok(true, "Owner creates a container");
const blob = container.getBlockBlobClient("hello.txt");
await refused(() => blob.upload("hello", 5), 403, "AuthorizationPermissionMismatch",
    "Owner cannot upload a blob");
await refused(async () => { for await (const _ of container.listBlobsFlat()) {} }, 403,
    "AuthorizationPermissionMismatch", "Owner cannot list blobs");

// 3. Grant Storage Blob Data Contributor at the account, through ARM.
const assignment = `${ assignments }/${ randomUUID() }`;
r = await arm("PUT", `${ assignment }?api-version=2022-04-01`, {
    properties: {
        roleDefinitionId: `/subscriptions/${ SUB }/providers/Microsoft.Authorization`
            + `/roleDefinitions/${ BLOB_DATA_CONTRIBUTOR }`,
        principalId: OWNER_OID,
        principalType: "ServicePrincipal",
    },
});
ok(r.status === 201, `grant Storage Blob Data Contributor -> ${ r.status }`);

// 4. The blob lifecycle with a bearer token, re-signed for Azurite.
await blob.upload("hello", 5, { blobHTTPHeaders: { blobContentType: "text/plain" } });
ok(true, "upload");
let body = (await blob.downloadToBuffer()).toString();
ok(body === "hello", `download -> ${ body }`);
const names = [];
for await (const b of container.listBlobsFlat()) names.push(b.name);
ok(names.includes("hello.txt"), `listBlobsFlat -> ${ names }`);
const props = await blob.getProperties();
ok(props.contentType === "text/plain", `getProperties -> ${ props.contentType }`);

// 5. Key-based auth passes through to Azurite: the account key from
// listKeys, and a service SAS signed with it.
r = await arm("POST", `${ ACCOUNT_ID }/listKeys?api-version=2025-08-01`);
ok(r.status === 200 && r.body.keys.length === 2, `listKeys -> ${ r.body.keys.map(k => k.keyName) }`);
const keyCred = new StorageSharedKeyCredential(ACCOUNT, r.body.keys[0].value);
body = (await new BlobServiceClient(BLOB_URL, keyCred).getContainerClient(CONTAINER)
    .getBlobClient("hello.txt").downloadToBuffer()).toString();
ok(body === "hello", "download with the account key");
const expiresOn = new Date(Date.now() + 3600e3);
const sas = generateBlobSASQueryParameters({ containerName: CONTAINER, blobName: "hello.txt",
    permissions: BlobSASPermissions.parse("r"), expiresOn }, keyCred).toString();
const viaSAS = new BlobServiceClient(`${ BLOB_URL }?${ sas }`).getContainerClient(CONTAINER);
body = (await viaSAS.getBlobClient("hello.txt").downloadToBuffer()).toString();
ok(body === "hello", "download with a service SAS");
await refused(() => viaSAS.getBlockBlobClient("hello.txt").upload("x", 1), 403,
    "AuthorizationPermissionMismatch", "a read-only service SAS cannot write");

// 6. Identity-based SAS: a user delegation key from Armite, a SAS
// signed with it, authorized as the Owner would be - at use time.
const udk = await service.getUserDelegationKey(new Date(), expiresOn);
ok(udk.signedObjectId === OWNER_OID, `getUserDelegationKey -> oid ${ udk.signedObjectId }`);
const udsas = generateBlobSASQueryParameters({ containerName: CONTAINER, blobName: "hello.txt",
    permissions: BlobSASPermissions.parse("r"), expiresOn }, udk, ACCOUNT).toString();
const viaUD = new BlobServiceClient(`${ BLOB_URL }?${ udsas }`).getContainerClient(CONTAINER);
body = (await viaUD.getBlobClient("hello.txt").downloadToBuffer()).toString();
ok(body === "hello", "download with a user delegation SAS");

// 7. Revocation is instant and reaches the SAS: the evaluator and the
// provider share one store, and the SAS is checked against it at use.
r = await arm("DELETE", `${ assignment }?api-version=2022-04-01`);
ok(r.status === 200 || r.status === 204, `revoke the assignment -> ${ r.status }`);
await refused(() => blob.downloadToBuffer(), 403, "AuthorizationPermissionMismatch",
    "Owner cannot read after revocation");
await refused(() => viaUD.getBlobClient("hello.txt").downloadToBuffer(), 403,
    "AuthorizationPermissionMismatch", "the user delegation SAS dies with the grant");

// 8. The account property that turns key access off, enforced here.
r = await arm("PATCH", `${ ACCOUNT_ID }?api-version=2025-08-01`,
    { properties: { allowSharedKeyAccess: false } });
ok(r.status === 200, "allowSharedKeyAccess=false");
await refused(() => new BlobServiceClient(BLOB_URL, keyCred).getContainerClient(CONTAINER)
    .getBlobClient("hello.txt").downloadToBuffer(), 403, "KeyBasedAuthenticationNotPermitted",
    "the account key is refused");
await refused(() => viaSAS.getBlobClient("hello.txt").downloadToBuffer(), 403,
    "KeyBasedAuthenticationNotPermitted", "the service SAS is refused");
r = await arm("PATCH", `${ ACCOUNT_ID }?api-version=2025-08-01`,
    { properties: { allowSharedKeyAccess: true } });
ok(r.status === 200, "allowSharedKeyAccess=true again");

console.log("PASS");
