import React, { useState } from "react";

/*
 SecureChat v2.0 - Two-party chat demo (ALL algorithms)
 - AES-256-GCM session keys per party
 - RSA-OAEP (2048) for wrap/unwrap
 - ECDH P-256 derive
 - RSA-PSS (2048, SHA-256) for signing/verification
 - ECDSA (P-256, SHA-256) for signing/verification (NEW)
 Uses Web Crypto API only.
*/

const bufToBase64 = (buf) => {
  if (!buf) return "";
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
};
const base64ToBuf = (b64) => {
  if (!b64) return new ArrayBuffer(0);
  const binary = window.atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};
const strToBuf = (s) => new TextEncoder().encode(s);
const bufToStr = (b) => new TextDecoder().decode(b);

export default function App() {
  const [log, setLog] = useState([]);
  const addLog = (t) => setLog((l) => [t, ...l].slice(0, 500));

  // keys/artifacts for A and B (extended with ecdsa)
  const [keysA, setKeysA] = useState({
    aes: null,
    aesB64: "",
    rsaWrap: null,
    rsaSign: null,
    ecdh: null,
    ecdhPubB64: "",
    ecdsaSign: null, // NEW
  });
  const [keysB, setKeysB] = useState({
    aes: null,
    aesB64: "",
    rsaWrap: null,
    rsaSign: null,
    ecdh: null,
    ecdhPubB64: "",
    ecdsaSign: null, // NEW
  });

  // chat messages array
  const [messages, setMessages] = useState([]);

  // input fields
  const [inputA, setInputA] = useState("Hello from A!");
  const [inputB, setInputB] = useState("Hello from B!");

  // helper exports
  const exportKeyRawB64 = async (key) => {
    const raw = await window.crypto.subtle.exportKey("raw", key);
    return bufToBase64(raw);
  };
  const exportPublicSPKIB64 = async (pub) => {
    const spki = await window.crypto.subtle.exportKey("spki", pub);
    return bufToBase64(spki);
  };

  // generate keys for A (now includes ECDSA)
  const generateKeysForA = async () => {
    // AES
    const aes = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
    const aesB64 = await exportKeyRawB64(aes);

    // RSA wrap
    const rsaWrap = await window.crypto.subtle.generateKey({
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }, true, ["wrapKey", "unwrapKey"]);

    // RSA sign (PSS)
    const rsaSign = await window.crypto.subtle.generateKey({
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }, true, ["sign", "verify"]);

    // ECDH
    const ecdh = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const ecdhPubB64 = bufToBase64(await window.crypto.subtle.exportKey("raw", ecdh.publicKey));

    // ECDSA (P-256) for signing (NEW)
    const ecdsaSign = await window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

    setKeysA({ aes, aesB64, rsaWrap, rsaSign, ecdh, ecdhPubB64, ecdsaSign });
    addLog("✅ تم توليد مفاتيح الطرف A (AES,RSA-OAEP,RSA-PSS,ECDH,ECDSA)");
  };

  // generate keys for B (includes ECDSA)
  const generateKeysForB = async () => {
    const aes = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
    const aesB64 = await exportKeyRawB64(aes);

    const rsaWrap = await window.crypto.subtle.generateKey({
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }, true, ["wrapKey", "unwrapKey"]);

    const rsaSign = await window.crypto.subtle.generateKey({
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }, true, ["sign", "verify"]);

    const ecdh = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const ecdhPubB64 = bufToBase64(await window.crypto.subtle.exportKey("raw", ecdh.publicKey));

    const ecdsaSign = await window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

    setKeysB({ aes, aesB64, rsaWrap, rsaSign, ecdh, ecdhPubB64, ecdsaSign });
    addLog("✅ تم توليد مفاتيح الطرف B (AES,RSA-OAEP,RSA-PSS,ECDH,ECDSA)");
  };

  // wrap AES from A to B using B's RSA public key
  const wrapAesAtoB = async () => {
    if (!keysA.aes || !keysB.rsaWrap) return addLog("⚠️ أنشئ مفاتيح A و B أولاً");
    const wrapped = await window.crypto.subtle.wrapKey("raw", keysA.aes, keysB.rsaWrap.publicKey, { name: "RSA-OAEP" });
    addLog("🔁 A غلّف مفتاح AES بواسطة RSA-OAEP (لـ B)");
    const unwrapped = await window.crypto.subtle.unwrapKey("raw", wrapped, keysB.rsaWrap.privateKey, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const raw = await window.crypto.subtle.exportKey("raw", unwrapped);
    const b64 = bufToBase64(raw);
    setKeysB((k) => ({ ...k, aes: unwrapped, aesB64: b64 }));
    addLog("✅ B فكّ غلاف AES واستلم المفتاح (Base64 shown)");
  };

  // derive shared AES via ECDH (fill both sides)
  const deriveSharedAesViaEcdh = async () => {
    if (!keysA.ecdh || !keysB.ecdh) return addLog("⚠️ أنشئ مفاتيح ECDH للطرفين أولًا");
    const derivedA = await window.crypto.subtle.deriveKey({ name: "ECDH", public: keysB.ecdh.publicKey }, keysA.ecdh.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const derivedB = await window.crypto.subtle.deriveKey({ name: "ECDH", public: keysA.ecdh.publicKey }, keysB.ecdh.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const rawA = await window.crypto.subtle.exportKey("raw", derivedA);
    const rawB = await window.crypto.subtle.exportKey("raw", derivedB);
    const b64A = bufToBase64(rawA);
    const b64B = bufToBase64(rawB);
    if (b64A === b64B) {
      setKeysA((k) => ({ ...k, aes: derivedA, aesB64: b64A }));
      setKeysB((k) => ({ ...k, aes: derivedB, aesB64: b64B }));
      addLog("🔁 تم اشتقاق AES مشترك عبر ECDH (مطابق)");
    } else {
      addLog("⚠️ خطأ: القيم المشتقة غير متطابقة");
    }
  };

  // send message A->B with chosen signature algorithm ('rsa' or 'ecdsa')
  const sendFromAtoB = async (plaintext, sigAlg = "rsa") => {
    if (!keysB.aes) return addLog("⚠️ B ليس لديه AES لفك التشفير — استخدم ECDH أو wrapAesAtoB");
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const ptBuf = strToBuf(plaintext);
      const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, keysB.aes, ptBuf);
      const encU8 = new Uint8Array(encrypted);
      const tag = encU8.slice(encU8.length - 16);
      const ct = encU8.slice(0, encU8.length - 16);

      // choose signature algorithm
      let sig;
      if (sigAlg === "rsa") {
        if (!keysA.rsaSign) return addLog("⚠️ A ليس لديه مفتاح RSA-PSS للتوقيع");
        sig = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, keysA.rsaSign.privateKey, ptBuf);
      } else {
        if (!keysA.ecdsaSign) return addLog("⚠️ A ليس لديه مفتاح ECDSA للتوقيع");
        sig = await window.crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, keysA.ecdsaSign.privateKey, ptBuf);
      }

      const msg = {
        from: "A",
        ctB64: bufToBase64(ct.buffer),
        ivB64: bufToBase64(iv.buffer),
        tagB64: bufToBase64(tag.buffer),
        sigB64: bufToBase64(sig),
        sigAlg,
        plain_cached: "[encrypted]",
        verified: null,
        time: Date.now(),
      };
      setMessages((m) => [...m, msg]);
      addLog(`📤 A أرسل رسالة مشفّرة إلى B (sig=${sigAlg})`);
    } catch (e) {
      addLog("❌ خطأ عند إرسال A→B: " + (e.message || e));
    }
  };

  // process message for B (decryption + verification based on sigAlg)
  const processMessageForB = async (msgIndex) => {
    const msg = messages[msgIndex];
    if (!msg || msg.from !== "A") return addLog("⚠️ هذه الرسالة ليست من A");
    if (!keysB.aes) return addLog("⚠️ B ليس لديه AES لفك التشفير");
    try {
      const ct = new Uint8Array(base64ToBuf(msg.ctB64));
      const tag = new Uint8Array(base64ToBuf(msg.tagB64));
      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct, 0);
      combined.set(tag, ct.length);
      const iv = new Uint8Array(base64ToBuf(msg.ivB64));
      const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, keysB.aes, combined.buffer);
      const plain = bufToStr(plainBuf);

      let valid = false;
      if (msg.sigAlg === "rsa") {
        if (!keysA.rsaSign) return addLog("⚠️ مفتاح توقيع A (RSA) غير متوفر");
        valid = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, keysA.rsaSign.publicKey, base64ToBuf(msg.sigB64), strToBuf(plain));
      } else {
        if (!keysA.ecdsaSign) return addLog("⚠️ مفتاح توقيع A (ECDSA) غير متوفر");
        valid = await window.crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, keysA.ecdsaSign.publicKey, base64ToBuf(msg.sigB64), strToBuf(plain));
      }

      setMessages((m) => m.map((x, i) => i === msgIndex ? { ...x, verified: valid, plain_cached: plain } : x));
      addLog(valid ? "✅ B: تم فك التشفير والتحقق بنجاح" : "❌ B: التوقيع غير صالح");
    } catch (e) {
      addLog("❌ B: فشل في فك التشفير أو التحقق: " + (e.message || e));
      setMessages((m) => m.map((x, i) => i === msgIndex ? { ...x, verified: false } : x));
    }
  };

  // symmetric: send B->A with chosen signature algorithm
  const sendFromBtoA = async (plaintext, sigAlg = "rsa") => {
    if (!keysA.aes) return addLog("⚠️ A ليس لديه AES لفك التشفير — استخدم ECDH أو wrapAesAtoB");
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const ptBuf = strToBuf(plaintext);
      const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, keysA.aes, ptBuf);
      const encU8 = new Uint8Array(encrypted);
      const tag = encU8.slice(encU8.length - 16);
      const ct = encU8.slice(0, encU8.length - 16);

      let sig;
      if (sigAlg === "rsa") {
        if (!keysB.rsaSign) return addLog("⚠️ B ليس لديه مفتاح RSA-PSS للتوقيع");
        sig = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, keysB.rsaSign.privateKey, ptBuf);
      } else {
        if (!keysB.ecdsaSign) return addLog("⚠️ B ليس لديه مفتاح ECDSA للتوقيع");
        sig = await window.crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, keysB.ecdsaSign.privateKey, ptBuf);
      }

      const msg = {
        from: "B",
        ctB64: bufToBase64(ct.buffer),
        ivB64: bufToBase64(iv.buffer),
        tagB64: bufToBase64(tag.buffer),
        sigB64: bufToBase64(sig),
        sigAlg,
        plain_cached: "[encrypted]",
        verified: null,
        time: Date.now(),
      };
      setMessages((m) => [...m, msg]);
      addLog(`📤 B أرسل رسالة مشفّرة إلى A (sig=${sigAlg})`);
    } catch (e) {
      addLog("❌ خطأ عند إرسال B→A: " + (e.message || e));
    }
  };

  // process message for A
  const processMessageForA = async (msgIndex) => {
    const msg = messages[msgIndex];
    if (!msg || msg.from !== "B") return addLog("⚠️ هذه الرسالة ليست من B");
    if (!keysA.aes) return addLog("⚠️ A ليس لديه AES لفك التشفير");
    try {
      const ct = new Uint8Array(base64ToBuf(msg.ctB64));
      const tag = new Uint8Array(base64ToBuf(msg.tagB64));
      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct, 0);
      combined.set(tag, ct.length);
      const iv = new Uint8Array(base64ToBuf(msg.ivB64));
      const plainBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, keysA.aes, combined.buffer);
      const plain = bufToStr(plainBuf);

      let valid = false;
      if (msg.sigAlg === "rsa") {
        if (!keysB.rsaSign) return addLog("⚠️ مفتاح توقيع B (RSA) غير متوفر");
        valid = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, keysB.rsaSign.publicKey, base64ToBuf(msg.sigB64), strToBuf(plain));
      } else {
        if (!keysB.ecdsaSign) return addLog("⚠️ مفتاح توقيع B (ECDSA) غير متوفر");
        valid = await window.crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, keysB.ecdsaSign.publicKey, base64ToBuf(msg.sigB64), strToBuf(plain));
      }

      setMessages((m) => m.map((x, i) => i === msgIndex ? { ...x, verified: valid, plain_cached: plain } : x));
      addLog(valid ? "✅ A: تم فك التشفير والتحقق بنجاح" : "❌ A: التوقيع غير صالح");
    } catch (e) {
      addLog("❌ A: فشل في فك التشفير أو التحقق: " + (e.message || e));
      setMessages((m) => m.map((x, i) => i === msgIndex ? { ...x, verified: false } : x));
    }
  };

  // tamper message - flip first byte of ciphertext for message i
  const tamperMessage = (idx) => {
    const msg = messages[idx];
    if (!msg) return addLog("⚠️ الرسالة غير موجودة");
    const arr = new Uint8Array(base64ToBuf(msg.ctB64));
    arr[0] = arr[0] ^ 1;
    const newCt = bufToBase64(arr.buffer);
    setMessages((m) => m.map((x, i) => i === idx ? { ...x, ctB64: newCt } : x));
    addLog("⚠️ تم العبث برسالة #" + idx);
  };

  // utility to show public keys (Base64) in log
  const showPublics = async () => {
    const out = {};
    if (keysA.rsaWrap) out.A_rsaWrap_pub = await exportPublicSPKIB64(keysA.rsaWrap.publicKey);
    if (keysA.rsaSign) out.A_rsaSign_pub = await exportPublicSPKIB64(keysA.rsaSign.publicKey);
    if (keysA.ecdsaSign) out.A_ecdsa_pub = await exportPublicSPKIB64(keysA.ecdsaSign.publicKey);
    if (keysB.rsaWrap) out.B_rsaWrap_pub = await exportPublicSPKIB64(keysB.rsaWrap.publicKey);
    if (keysB.rsaSign) out.B_rsaSign_pub = await exportPublicSPKIB64(keysB.rsaSign.publicKey);
    if (keysB.ecdsaSign) out.B_ecdsa_pub = await exportPublicSPKIB64(keysB.ecdsaSign.publicKey);
    addLog(JSON.stringify(out, null, 2));
  };

  return (
    <div className="container" style={{ direction: "rtl", padding: 18, fontFamily: "sans-serif" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700 }}>SecureChat v2.0 — دردشة طرفين (A ↔ B)</div>
          <div style={{ fontSize: 13, color: "#6b7280" }}>AES-256-GCM · RSA-OAEP(2048) · ECDH P-256 · RSA-PSS + ECDSA (SHA-256)</div>
        </div>
        <div style={{ fontSize: 13, color: "#374151" }}>Web Crypto API — Demo</div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 12 }}>
        {/* Left column: controls for A */}
        <div className="section">
          <h3>الطرف A</h3>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="button" onClick={generateKeysForA}>توليد مفاتيح A</button>
            <button className="button" onClick={wrapAesAtoB}>A: غلّف AES وأرسله إلى B</button>
            <button className="button" onClick={deriveSharedAesViaEcdh}>اشتقاق AES عبر ECDH</button>
            <button className="button" onClick={showPublics}>عرض المفاتيح العامة</button>
          </div>
          <div style={{ marginTop: 8, fontSize: 12 }}>
            <div>AES (A) Base64: <code className="code">{keysA.aesB64 || "—"}</code></div>
            <div>ECDH pub (A): <code className="code">{keysA.ecdhPubB64 || "—"}</code></div>
          </div>

          <div style={{ marginTop: 10 }}>
            <label>أرسل رسالة من A → B</label>
            <textarea rows={2} value={inputA} onChange={(e)=>setInputA(e.target.value)} style={{ width: "100%", marginTop: 6 }} />
            <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
              <button className="button" onClick={()=>sendFromAtoB(inputA, "rsa")}>أرسل A→B (RSA-PSS)</button>
              <button className="button" onClick={()=>sendFromAtoB(inputA, "ecdsa")}>أرسل A→B (ECDSA)</button>
            </div>
          </div>
        </div>

        {/* Right column: controls for B */}
        <div className="section">
          <h3>الطرف B</h3>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="button" onClick={generateKeysForB}>توليد مفاتيح B</button>
            <button className="button" onClick={()=>{ addLog("ملاحظة: يمكنك استخدام نفس زر ECDH في A أو wrap من A->B"); }}>ملاحظة</button>
          </div>
          <div style={{ marginTop: 8, fontSize: 12 }}>
            <div>AES (B) Base64: <code className="code">{keysB.aesB64 || "—"}</code></div>
            <div>ECDH pub (B): <code className="code">{keysB.ecdhPubB64 || "—"}</code></div>
          </div>

          <div style={{ marginTop: 10 }}>
            <label>أرسل رسالة من B → A</label>
            <textarea rows={2} value={inputB} onChange={(e)=>setInputB(e.target.value)} style={{ width: "100%", marginTop: 6 }} />
            <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
              <button className="button" onClick={()=>sendFromBtoA(inputB, "rsa")}>أرسل B→A (RSA-PSS)</button>
              <button className="button" onClick={()=>sendFromBtoA(inputB, "ecdsa")}>أرسل B→A (ECDSA)</button>
            </div>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 12 }} className="section">
        <h3>سجل المحادثة (رسائل مشفّرة)</h3>
        <div style={{ maxHeight: 320, overflow: "auto", background: "#f8fafc", padding: 8 }}>
          {messages.length === 0 ? <div style={{ color: "#9ca3af" }}>لا توجد رسائل بعد</div> :
            messages.map((m, idx) => (
              <div key={idx} style={{ borderBottom: "1px solid #eee", padding: 8 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <div><strong>{m.from === "A" ? "من A" : "من B"}</strong> · {new Date(m.time).toLocaleTimeString()}</div>
                  <div style={{ fontSize: 12 }}>
                    {m.verified === null ? <em>قيد الانتظار</em> : (m.verified ? <span style={{ color: "green" }}>مصدق ✅</span> : <span style={{ color: "red" }}>غير مصدق ❌</span>)}
                  </div>
                </div>
                <div style={{ marginTop: 6, fontSize: 13 }}>
                  <div>الخوارزمية: <strong>{m.sigAlg === "rsa" ? "RSA-PSS" : "ECDSA (P-256)"}</strong></div>
                  <div>Ciphertext: <code className="code">{m.ctB64}</code></div>
                  <div>IV: <code className="code">{m.ivB64}</code></div>
                  <div>Tag: <code className="code">{m.tagB64}</code></div>
                  <div>Signature: <code className="code">{m.sigB64}</code></div>
                  <div style={{ marginTop: 6 }}>النص (إن استلم وفك): <strong>{m.plain_cached}</strong></div>
                </div>

                <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
                  {m.from === "A" ? (
                    <>
                      <button className="button" onClick={()=>processMessageForB(idx)}>B: فك+تحقق</button>
                      <button className="button" onClick={()=>tamperMessage(idx)}>التلاعب</button>
                    </>
                  ) : (
                    <>
                      <button className="button" onClick={()=>processMessageForA(idx)}>A: فك+تحقق</button>
                      <button className="button" onClick={()=>tamperMessage(idx)}>التلاعب</button>
                    </>
                  )}
                </div>
              </div>
            ))
          }
        </div>
      </div>

      <aside style={{ marginTop: 12 }} className="section">
        <h3>سجل الأحداث</h3>
        <div className="log" style={{ maxHeight: 240, overflow: "auto", padding: 8 }}>
          {log.length === 0 ? <div style={{ color: "#9ca3af" }}>لا توجد أحداث بعد</div> :
            <ul style={{ paddingLeft: 12 }}>{log.map((l,i)=><li key={i} style={{ marginBottom: 6 }}>{l}</li>)}</ul>}
        </div>
      </aside>

      <footer style={{ marginTop: 12, padding: 8, textAlign: "center", color: "#6b7280" }}>
        SecureChat v2.0 — Two-party chat demo (RSA-PSS & ECDSA added)
      </footer>
    </div>
  );
}
