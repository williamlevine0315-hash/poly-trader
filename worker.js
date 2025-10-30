// Modules Worker (ESM) — uses the BROWSER build of clob-client
// Works on Cloudflare without node core modules.

import { ClobClient } from "@polymarket/clob-client/dist/browser.js";
import { ethers } from "ethers";

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/health") {
        return j({ ok: true, name: "poly-trader", time: Date.now() });
      }
      if (url.pathname === "/trade" && request.method === "POST") {
        return await handleTrade(request, env);
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return j({ ok: false, error: e.message }, 500);
    }
  },
};

async function handleTrade(request, env) {
  // HMAC check from HUD
  const sig = request.headers.get("X-HUD-Signature") || "";
  if (!sig.startsWith("sha256=")) return j({ ok:false, error:"Missing/invalid signature" }, 401);
  const body = await request.text();
  if (!(await verifyHmac(env.HUD_SHARED_SECRET, body, sig.slice(7)))) {
    return j({ ok:false, error:"Signature mismatch" }, 401);
  }

  let payload;
  try { payload = JSON.parse(body); } catch { return j({ ok:false, error:"Bad JSON" }, 400); }

  const { conditionId, marketId, side, ask, amountUsd, slippage = 0.01 } = payload;
  if (!side || !amountUsd || !ask) return j({ ok:false, error:"Missing side/amountUsd/ask" }, 400);
  if (!["YES","NO"].includes(side)) return j({ ok:false, error:"side must be YES or NO" }, 400);

  // Resolve tokenId (Gamma)
  const resolved = await resolveTokenId({ conditionId, marketId, side });
  if (!resolved.ok) return j(resolved, 400);
  const { tokenId, priceFromBook } = resolved;

  // Price/shares
  const price = clamp01(Number(ask) * (1 + Number(slippage || 0)));
  const shares = amountUsd / price;

  // Polymarket client (browser build)
  const host = env.POLY_HOST || "https://clob.polymarket.com";
  const chain = Number(env.CHAIN_ID || 137);

  const signer = new ethers.Wallet(env.PRIVATE_KEY);
  const client = new ClobClient(host, chain, signer);

  // Ensure API key exists
  await client.createOrDeriveApiKey(signer.address.toLowerCase());

  const clobSide = side === "YES" ? 0 : 1;
  const order = {
    token_id: tokenId,
    price,              // 0..1
    size: shares,       // shares
    side: clobSide,     // 0 YES, 1 NO
    client_order_id: `hud-${Date.now()}`,
    time_in_force: "IOC",
    post_only: false,
  };

  let placed;
  try {
    placed = await client.place(order);
  } catch (e) {
    return j({ ok:false, error:`place() failed: ${e.message}` }, 502);
  }

  return j({
    ok: true,
    order: placed,
    fills: { sharesBought: shares, avgPrice: price, costUsd: shares * price },
    meta: { tokenId, priceFromBook },
  });
}

async function resolveTokenId({ conditionId, marketId, side }) {
  try {
    let url;
    if (conditionId) {
      url = `https://gamma-api.polymarket.com/markets?limit=50&active=true&condition_ids=${encodeURIComponent(conditionId)}`;
    } else if (marketId) {
      url = `https://gamma-api.polymarket.com/markets?limit=50&active=true&slug=${encodeURIComponent(marketId)}`;
    } else {
      return { ok:false, error:"No conditionId/marketId to resolve tokenId" };
    }
    const r = await fetch(url, { cf: { cacheTtl: 3, cacheEverything: true } });
    if (!r.ok) return { ok:false, error:`Gamma API ${r.status}` };
    const arr = await r.json();
    if (!Array.isArray(arr) || arr.length === 0) return { ok:false, error:"No market found" };
    const m = arr[0];

    const wantNames = side === "YES" ? ["Up","Yes","YES"] : ["Down","No","NO"];
    const idx = (m.outcomes || []).findIndex(o => wantNames.includes(String(o).trim()));
    const use = idx >= 0 ? idx : (side === "YES" ? 0 : 1);

    const tokenId = m.tokens?.[use]?.token_id || m.tokens?.[use]?.tokenId;
    if (!tokenId) return { ok:false, error:"Missing tokenId" };

    let priceFromBook;
    if (m.best_ask && Array.isArray(m.best_ask) && m.best_ask[use] != null) {
      const v = Number(m.best_ask[use]); if (Number.isFinite(v)) priceFromBook = clamp01(v);
    }
    return { ok:true, tokenId, priceFromBook };
  } catch (e) {
    return { ok:false, error:`resolveTokenId error: ${e.message}` };
  }
}

// HMAC with Web Crypto (Workers has `crypto.subtle`)
async function verifyHmac(secret, message, hexSig) {
  if (!secret) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign","verify"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  const calcHex = [...new Uint8Array(sigBuf)].map(b=>b.toString(16).padStart(2,'0')).join('');
  return timingSafeEqual(calcHex, hexSig.toLowerCase());
}

function timingSafeEqual(a,b){ if(a.length!==b.length) return false; let x=0; for(let i=0;i<a.length;i++) x|=(a.charCodeAt(i)^b.charCodeAt(i)); return x===0; }
function clamp01(x){ x=Number(x); if(!Number.isFinite(x)) return NaN; return Math.max(0, Math.min(1, x)); }
function j(obj, status=200){ return new Response(JSON.stringify(obj), { status, headers: { "content-type":"application/json" } }); }
