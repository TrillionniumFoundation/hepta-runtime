function buildRecoveryTransport(files,h){
 const concat=parts=>h.concat(parts);
 const text=s=>h.utf8(s);
 const zero=n=>new Uint8Array(n);
 function put(dst,offset,s,width){const raw=text(s);if(raw.length>width)throw Error("header width");dst.set(raw,offset);}
 function oct(n,width){const s=n.toString(8);if(s.length>width-1)throw Error("octal overflow");return s.padStart(width-1,"0")+"\0";}
 const parts=[];
 for(const name of Object.keys(files).sort()){
  const item=files[name],raw=text(item.content);
  if(raw.length!==item.bytes||h.sha256(raw)!==item.sha256||text(name).length>100)throw Error("member identity");
  const hd=zero(512);
  put(hd,0,name,100);put(hd,100,oct(0o600,8),8);put(hd,108,oct(0,8),8);put(hd,116,oct(0,8),8);
  put(hd,124,oct(raw.length,12),12);put(hd,136,oct(0,12),12);put(hd,148,"        ",8);
  hd[156]=48;put(hd,257,"ustar\0",6);put(hd,263,"00",2);
  const sum=hd.reduce((a,b)=>a+b,0);put(hd,148,sum.toString(8).padStart(6,"0")+"\0 ",8);
  parts.push(hd,raw,zero((512-raw.length%512)%512));
 }
 parts.push(zero(1024));
 let tar=concat(parts);tar=concat([tar,zero((10240-tar.length%10240)%10240)]);
 const table=new Uint32Array(256);
 for(let i=0;i<256;i++){let c=i;for(let n=0;n<8;n++)c=c&1?0xedb88320^(c>>>1):c>>>1;table[i]=c>>>0;}
 let crc=0xffffffff;for(const b of tar)crc=table[(crc^b)&255]^(crc>>>8);crc=(crc^0xffffffff)>>>0;
 const gz=[new Uint8Array([31,139,8,0,0,0,0,0,0,255])];
 for(let off=0;off<tar.length;off+=65535){const n=Math.min(65535,tar.length-off),last=off+n===tar.length;
  gz.push(new Uint8Array([last?1:0,n&255,n>>>8,(~n)&255,((~n)>>>8)&255]),tar.slice(off,off+n));
 }
 const trailer=zero(8),dv=new DataView(trailer.buffer);dv.setUint32(0,crc,true);dv.setUint32(4,tar.length>>>0,true);gz.push(trailer);
 const archive=concat(gz);
 let cursor=10,blocks=[],seenFinal=false;
 while(!seenFinal){const flag=archive[cursor++];if((flag&254)!==0)throw Error("stored block expected");seenFinal=!!(flag&1);
  const n=archive[cursor]|archive[cursor+1]<<8,inv=archive[cursor+2]|archive[cursor+3]<<8;cursor+=4;
  if((n^inv)!==65535)throw Error("stored length");blocks.push(archive.slice(cursor,cursor+n));cursor+=n;
 }
 const decoded=concat(blocks);if(cursor+8!==archive.length||h.sha256(decoded)!==h.sha256(tar))throw Error("stored gzip roundtrip");
 const utf=raw=>h.unutf8(raw).replace(/\0.*$/s,"");
 const selected=[];let offset=0;
 while(offset+512<=tar.length){const hd=tar.slice(offset,offset+512);if(hd.every(x=>x===0))break;
  const name=utf(hd.slice(0,100)),size=parseInt(utf(hd.slice(124,136)),8),expected=parseInt(utf(hd.slice(148,156)).trim(),8);
  const check=hd.slice();check.fill(32,148,156);if(check.reduce((a,b)=>a+b,0)!==expected||hd[156]!==48)throw Error("tar header");
  const raw=tar.slice(offset+512,offset+512+size),file=files[name];
  if(!file||raw.length!==file.bytes||h.sha256(raw)!==file.sha256||selected.includes(name))throw Error("tar member mismatch");
  selected.push(name);offset+=512+Math.ceil(size/512)*512;
 }
 if(selected.length!==Object.keys(files).length||tar.slice(offset).some(x=>x!==0))throw Error("tar trailing or inventory");
 return {archive,tarBytes:tar.length,crc32:crc,memberCount:selected.length,payloadBytes:Object.values(files).reduce((a,b)=>a+b.bytes,0)};
}
