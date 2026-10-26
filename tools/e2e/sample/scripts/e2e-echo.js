// E2E: script-echo-response — answers locally, no upstream needed.
console.log("e2e-echo script ran for " + $request.url);
$done({ status: "HTTP/1.1 200 OK", headers: { "Content-Type": "text/plain", "X-E2E": "echo" }, body: "e2e-echo-ok" });
