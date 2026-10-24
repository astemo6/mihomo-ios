// Dev rig (xmly_jsc_bun_test.go, TERN_BUN=path/to/bun): a stand-in for PacketTunnel/JSCScriptEngine.swift that
// runs scripts in JavaScriptCore (Bun's JSC, JIT off with BUN_JSC_useJIT=0 like an app extension) and calls the
// Go host back synchronously over stdin/stdout, one JSON object per line. One vm context per loaded script
// (= one JSContext per key on iOS), prelude evaluated in each, reused across runs.
const fs = require('fs');
const vm = require('vm');
const jsc = require('bun:jsc');

let inBuf = Buffer.alloc(0);
const chunk = Buffer.alloc(1 << 16);
function readLine() {
  for (;;) {
    const i = inBuf.indexOf(10);
    if (i >= 0) {
      const line = inBuf.subarray(0, i).toString('utf8');
      inBuf = inBuf.subarray(i + 1);
      return line;
    }
    let n;
    try { n = fs.readSync(0, chunk, 0, chunk.length, null); } catch (e) { if (e.code === 'EAGAIN') continue; throw e; }
    if (n === 0) process.exit(0);
    inBuf = Buffer.concat([inBuf, chunk.subarray(0, n)]);
  }
}
function send(o) { fs.writeSync(1, JSON.stringify(o) + '\n'); }
function ask(o) { send(o); return JSON.parse(readLine()); }

let prelude = '';
const entries = new Map(); // key -> {ctx, main, busy}
const runs = new Map(); // run -> entry
let curRun = 0;

function makeCtx() {
  const sandbox = {};
  const ctx = vm.createContext(sandbox);
  const T = {
    host: (op, arg) => ask({ t: 'host', run: curRun, op: String(op), arg: String(arg) }).r,
    put: (ab, off, len) => ask({ t: 'put', run: curRun, b64: Buffer.from(ab, off, len).toString('base64') }).r,
    take: (id) => { const r = ask({ t: 'take', run: curRun, id: id }); return new Uint8Array(Buffer.from(r.b64, 'base64')); },
  };
  Object.defineProperty(sandbox, '__tern', { value: T, enumerable: false });
  vm.runInContext(prelude, ctx, { filename: 'prelude.js' });
  return ctx;
}
function err(kind, e) { return JSON.stringify({ kind, message: String(e && e.stack || e) }); }

function stats(gc) {
  if (gc) Bun.gc(true);
  const h = jsc.heapStats();
  const m = process.memoryUsage();
  return { rss: m.rss, heapSize: h.heapSize, heapCapacity: h.heapCapacity, extra: h.extraMemorySize, objects: h.objectCount, globals: h.globalObjectCount, contexts: entries.size };
}

for (;;) {
  const c = JSON.parse(readLine());
  let r = '';
  try {
    switch (c.op) {
      case 'prepare': prelude = c.src; makeCtx(); break;
      case 'load': {
        const ctx = makeCtx();
        const main = vm.runInContext('(function(){ return function(){\n' + c.src + '\n}; })()', ctx, { filename: c.name + '.js' });
        entries.set(c.key, { ctx, main });
        break;
      }
      case 'drop': entries.delete(c.key); break;
      case 'collect': Bun.gc(true); break;
      case 'begin': {
        const e = entries.get(c.key);
        if (!e) { r = 'missing'; break; }
        runs.set(c.run, e);
        curRun = c.run;
        try {
          vm.runInContext('__tern_begin', e.ctx)(c.setup);
          e.main();
        } catch (x) { r = err('exception', x); }
        break;
      }
      case 'call': {
        const e = runs.get(c.run);
        curRun = c.run;
        try { vm.runInContext(c.fn, e.ctx)(c.arg); } catch (x) { r = err('exception', x); }
        break;
      }
      case 'end': runs.delete(c.run); break;
      case 'stats': r = JSON.stringify(stats(c.gc)); break;
    }
  } catch (x) { r = err('internal', x); }
  send({ t: 'ret', r });
}
