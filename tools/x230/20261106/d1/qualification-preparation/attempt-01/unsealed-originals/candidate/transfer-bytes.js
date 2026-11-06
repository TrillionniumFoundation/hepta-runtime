(function transferBytes() {
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function decode64(s) {
    if(s.length%4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw Error("invalid base64");
    const out=new Uint8Array(s.length/4*3-(s.endsWith("==")?2:s.endsWith("=")?1:0));
    for(let i=0,j=0;i<s.length;i+=4){
      const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==="="?0:alphabet.indexOf(s[i+2]),d=s[i+3]==="="?0:alphabet.indexOf(s[i+3]);
      const x=(a<<18)|(b<<12)|(c<<6)|d;
      if(j<out.length)out[j++]=x>>>16;if(j<out.length)out[j++]=x>>>8;if(j<out.length)out[j++]=x;
    } return out;
  }
  function encode64(bytes) {
    let s="";const blocks=[];
    for(let i=0;i<bytes.length;i+=3){const a=bytes[i],b=i+1<bytes.length?bytes[i+1]:0,c=i+2<bytes.length?bytes[i+2]:0,x=(a<<16)|(b<<8)|c;
      s+=alphabet[(x>>>18)&63]+alphabet[(x>>>12)&63]+(i+1<bytes.length?alphabet[(x>>>6)&63]:"=")+(i+2<bytes.length?alphabet[x&63]:"=");
      if(s.length>=32768){blocks.push(s);s="";}
    }blocks.push(s);return blocks.join("");
  }
  function utf8(s) {
    const a=[];for(const ch of s){let n=ch.codePointAt(0);
      if(n<128)a.push(n);else if(n<2048)a.push(192|(n>>>6),128|(n&63));else if(n<65536)a.push(224|(n>>>12),128|((n>>>6)&63),128|(n&63));else a.push(240|(n>>>18),128|((n>>>12)&63),128|((n>>>6)&63),128|(n&63));
    }return new Uint8Array(a);
  }
  function unutf8(bytes) { let s="";const a=[];for(const n of bytes){s+="%"+n.toString(16).padStart(2,"0");if(s.length>=32766){a.push(s);s="";}}a.push(s);return decodeURIComponent(a.join("")); }
  function pad(bytes){const n=Math.ceil((bytes.length+9)/64)*64,p=new Uint8Array(n);p.set(bytes);p[bytes.length]=128;const d=new DataView(p.buffer);d.setUint32(n-8,Math.floor(bytes.length/0x20000000));d.setUint32(n-4,(bytes.length*8)>>>0);return d;}
  const hex=xs=>Array.from(xs,x=>(x>>>0).toString(16).padStart(8,"0")).join("");
  function sha1(bytes){const d=pad(bytes),w=new Uint32Array(80),h=new Uint32Array([0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0]),rot=(v,n)=>(v<<n)|(v>>>(32-n));
    for(let p=0;p<d.byteLength;p+=64){for(let i=0;i<16;i++)w[i]=d.getUint32(p+4*i);for(let i=16;i<80;i++)w[i]=rot(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);let [a,b,c,e,f]=h;
      for(let i=0;i<80;i++){let g,k;if(i<20){g=(b&c)|(~b&e);k=0x5a827999;}else if(i<40){g=b^c^e;k=0x6ed9eba1;}else if(i<60){g=(b&c)|(b&e)|(c&e);k=0x8f1bbcdc;}else{g=b^c^e;k=0xca62c1d6;}
        const t=(rot(a,5)+g+f+k+w[i])>>>0;f=e;e=c;c=rot(b,30);b=a;a=t;
      }h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=e;h[4]+=f;
    }return hex(h);
  }
  function sha256(bytes){
    const primes=[];for(let n=2;primes.length<64;n++){let ok=true;for(const p of primes){if(p*p>n)break;if(n%p===0){ok=false;break;}}if(ok)primes.push(n);}
    const frac=x=>((x-Math.floor(x))*4294967296)>>>0,k=new Uint32Array(primes.map(x=>frac(Math.pow(x,1/3)))),h=new Uint32Array(primes.slice(0,8).map(x=>frac(Math.sqrt(x))));
    const d=pad(bytes),w=new Uint32Array(64),ro=(x,n)=>(x>>>n)|(x<<(32-n));
    for(let p=0;p<d.byteLength;p+=64){for(let i=0;i<16;i++)w[i]=d.getUint32(p+4*i);for(let i=16;i<64;i++){let x=w[i-15],y=w[i-2];w[i]=w[i-16]+(ro(x,7)^ro(x,18)^(x>>>3))+w[i-7]+(ro(y,17)^ro(y,19)^(y>>>10));}
      let[a,b,c,e,f,g,j,l]=h;
      for(let i=0;i<64;i++){const t1=(l+(ro(f,6)^ro(f,11)^ro(f,25))+((f&g)^(~f&j))+k[i]+w[i])>>>0,t2=((ro(a,2)^ro(a,13)^ro(a,22))+((a&b)^(a&c)^(b&c)))>>>0;l=j;j=g;g=f;f=(e+t1)>>>0;e=c;c=b;b=a;a=(t1+t2)>>>0;}
      h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=e;h[4]+=f;h[5]+=g;h[6]+=j;h[7]+=l;
    }return hex(h);
  }
  function gitBlob(bytes){const head=utf8("blob "+bytes.length+"\0"),full=new Uint8Array(head.length+bytes.length);full.set(head);full.set(bytes,head.length);return sha1(full);}
  function concat(arr){const n=arr.reduce((a,b)=>a+b.length,0),out=new Uint8Array(n);let p=0;for(const b of arr){out.set(b,p);p+=b.length;}return out;}
  return {decode64,encode64,utf8,unutf8,sha1,sha256,gitBlob,concat};
});
