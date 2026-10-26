// E2E: http-response body script on a public origin (network dependent).
console.log("e2e-resp script ran, status " + $response.status);
$done({ body: ($response.body || "") + "\n<!--e2e-resp-->" });
