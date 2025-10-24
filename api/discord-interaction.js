// api/discord-interaction.js
// Node serverless handler for Discord Interactions
// Works on Vercel / Netlify Functions / other Node serverless platforms.
// Requires env vars: PUBLIC_KEY (hex) and MAKE_WEBHOOK_URL (the Make custom webhook target).

import nacl from 'tweetnacl';
import { TextEncoder } from 'util';

export default async function handler(req, res) {
  try {
    // 1) Read Discord signature headers
    const signature = req.headers['x-signature-ed25519'] || req.headers['X-Signature-Ed25519'];
    const timestamp = req.headers['x-signature-timestamp'] || req.headers['X-Signature-Timestamp'];

    if (!signature || !timestamp) {
      return res.status(401).send('Missing signature headers');
    }

    // 2) Raw body is required for verification — get raw buffer
    const rawBody = await getRawBody(req);

    // 3) Convert strings/hex to Uint8Array
    const pubKeyHex = process.env.PUBLIC_KEY;
    if (!pubKeyHex) throw new Error('PUBLIC_KEY env var not set');

    const pubKey = hexToUint8Array(pubKeyHex);
    const sig = hexToUint8Array(signature);

    // 4) Construct message: timestamp + body
    const encoder = new TextEncoder();
    const msgUint8 = concatUint8Array(encoder.encode(timestamp), rawBody);

    // 5) Verify
    const valid = nacl.sign.detached.verify(msgUint8, sig, pubKey);
    if (!valid) {
      return res.status(401).send('Invalid request signature');
    }

    // 6) Parse JSON body (safe now)
    const body = JSON.parse(rawBody.toString());

    // 7) Handle ping (type 1) quickly
    if (body.type === 1) {
      // PONG
      return res.status(200).json({ type: 1 });
    }

    // For component interactions and other types: send an ephemeral acknowledgement back to user immediately
    // type 4 -> Channel message with source (we send a short ephemeral reply)
    const ack = {
      type: 4,
      data: {
        content: 'Thanks — your response has been recorded.',
        flags: 64 // 64 = EPHEMERAL so only clicker sees it
      }
    };

    // 8) Forward the payload to Make webhook (fire-and-forget via fetch)
    const makeWebhook = process.env.MAKE_WEBHOOK_URL;
    if (!makeWebhook) {
      // still acknowledge to Discord even if Make webhook missing
      res.status(200).json(ack);
      console.warn('MAKE_WEBHOOK_URL not set — payload not forwarded.');
      return;
    }

    // Forward contextual data: entire interaction + headers (we'll pass trimmed info)
    // Use non-blocking background forward but await so serverless doesn't terminate before sending (some platforms support event.waitUntil)
    fetch(makeWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        forwarded_at: new Date().toISOString(),
        interaction: body,
        headers: {
          'x-signature-ed25519': signature,
          'x-signature-timestamp': timestamp
        }
      })
    }).catch(err => {
      console.error('Failed to forward to Make webhook:', err);
    });

    // 9) Immediately ACK to Discord
    return res.status(200).json(ack);

  } catch (err) {
    console.error('Handler error:', err);
    return res.status(500).send('Server error');
  }
}

/* ---------- Helper functions ---------- */

function hexToUint8Array(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function concatUint8Array(a, b) {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

// Get raw request body as Uint8Array (works in Node serverless environments)
async function getRawBody(req) {
  // In Vercel/Next Serverless: req is a Node IncomingMessage; we can gather buffers
  if (req.rawBody) {
    // Some platforms (like Vercel) provide rawBody directly if configured
    return typeof req.rawBody === 'string' ? Buffer.from(req.rawBody) : req.rawBody;
  }
  // Otherwise gather the chunks
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', (err) => reject(err));
  });
}
