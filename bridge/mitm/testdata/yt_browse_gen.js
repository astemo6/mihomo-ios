// Generator for yt_browse_ad.bin (youtube_test.go): a youtubei/v1/browse protobuf built with
// youtube.response.js's own message types — three richItemContents, the middle one an ad (unknown field
// with "pagead", >1000 bytes, as the script's ad detector expects). To regenerate:
//   sed 's/var F=K.getInstance("YouTube");/globalThis.__yt={qr,d};return;&/' yt_youtube.response.js > patched.js
//   node yt_browse_gen.js   (writes browse.bin)
globalThis.$task={}; globalThis.$prefs={valueForKey(){return null},setValueForKey(){}}; globalThis.$done=()=>{};
require('./patched.js');
const {qr,d}=globalThis.__yt;
// BFS through the schema for the path to a field named richItemContents
function fieldsOf(T){return T.fields||[]}
const q=[[qr,[]]]; const seen=new Set(); let found=null;
while(q.length){const [T,path]=q.shift(); if(seen.has(T.typeName))continue; seen.add(T.typeName);
 for(const f of fieldsOf(T)){ if(f.name==='richItemContents'){found={path:[...path,{f,T}]};break}
   if(f.kind==='message'){q.push([f.T(),[...path,{f,T}]])} }
 if(found)break}
console.error(found.path.map(p=>p.T.typeName+'.'+p.f.name+(p.f.repeat?'[]':'')).join(' -> '));
const last=found.path[found.path.length-1]; const ItemT=last.f.T();
console.error('item type', ItemT.typeName, ItemT.fields.map(f=>f.no+':'+f.name));
// item with an unknown field carrying "pagead" (ad), and a clean item
function unknownItem(tagNo, payload){ const base=ItemT.toBinary(ItemT.create()); const p=Buffer.from(payload);
  const tag=[]; let v=(tagNo<<3)|2; while(v>=0x80){tag.push((v&0x7f)|0x80); v>>>=7} tag.push(v);
  const len=[]; v=p.length; while(v>=0x80){len.push((v&0x7f)|0x80); v>>>=7} len.push(v);
  return ItemT.fromBinary(new Uint8Array([...base,...tag,...len,...p])) }
const ad=unknownItem(500000, 'x'.repeat(600)+'pagead'+'y'.repeat(600));
const clean=unknownItem(500001, 'z'.repeat(1300));
// build the nested object
const root=qr.create(); let cur=root;
for(let i=0;i<found.path.length-1;i++){const {f}=found.path[i]; const child=f.T().create(); if(f.repeat){cur[f.name]=[child]}else{cur[f.name]=child} cur=child}
cur[last.f.name]=[clean,ad,clean];
const bin=qr.toBinary(root);
require('fs').writeFileSync('browse.bin', bin);
// verify round trip
const back=qr.fromBinary(bin); let n=0; (function walk(o){ if(o&&typeof o==='object'){ if(Array.isArray(o.richItemContents)) n=o.richItemContents.length; for(const k of Object.keys(o)) walk(o[k]) } })(back);
console.error('bytes', bin.length, 'items', n, 'pagead in bin', Buffer.from(bin).includes('pagead'));
