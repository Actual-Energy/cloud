const ALLOWED_ORIGIN = 'https://actual-energy.github.io'; // set this to your real site origin

function corsHeaders(origin){
  return {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data, status, origin){
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) }
  });
}

export default {
  async fetch(request, env){
    const origin = request.headers.get('Origin') || '';

    if(request.method === 'OPTIONS'){
      return new Response(null, { headers: corsHeaders(origin) });
    }
    if(request.method !== 'POST'){
      return json({ success: false, error: 'Method not allowed' }, 405, origin);
    }

    let body;
    try{
      body = await request.json();
    } catch{
      return json({ success: false, error: 'Invalid request body' }, 400, origin);
    }

    const { turnstileToken } = body || {};
    if(!turnstileToken){
      return json({ success: false, error: 'Missing verification token' }, 400, origin);
    }

    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET_KEY,
        response: turnstileToken,
        remoteip: request.headers.get('CF-Connecting-IP') || ''
      })
    });
    const verifyData = await verifyRes.json();

    if(!verifyData.success){
      return json({ success: false, error: 'Verification failed' }, 403, origin);
    }

    return json({ success: true }, 200, origin);
  }
};
