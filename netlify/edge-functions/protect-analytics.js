export default async (request, context) => {
  const origin = request.headers.get('origin');
  
  const allowedDomains = [
    'https://webabout.co.uk',
    'https://wonderful-sable-e155ef.netlify.app',
    'https://chiits.com',
    'https://floorstofit.com',
    'https://chilingirov.co.uk',
    'https://ankcommercial.co.uk',
    'https://remember2.click',
    'https://rememberto.click',
    'https://webapproach.co.uk'
  ];

  const isAllowedOrigin = allowedDomains.some(d => origin?.startsWith(d));

  // 1. Handle browser CORS preflight (OPTIONS requests)
  if (request.method === 'OPTIONS') {
    if (isAllowedOrigin) {
      const requestedHeaders = request.headers.get('access-control-request-headers') || 'Content-Type, x-umami-hostname';
      
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': requestedHeaders,
        },
      });
    }
    return new Response('Forbidden', { status: 403 });
  }

  // 2. Only inspect analytics tracking payloads at /api/send
  if (request.url.includes('/api/send')) {
    const referer = request.headers.get('referer');
    const isAllowedReferer = allowedDomains.some(d => referer?.startsWith(d));

    if (!isAllowedOrigin && !isAllowedReferer) {
      return new Response(JSON.stringify({ error: 'Unauthorized origin' }), {
        status: 403,
        headers: { 
          'content-type': 'application/json',
          'Access-Control-Allow-Origin': origin || '*'
        },
      });
    }
  }

  // 3. Preserve your true location by injecting Netlify's client IP into proxy headers
  const clientIp = context.ip;
  const newHeaders = new Headers(request.headers);
  if (clientIp) {
    newHeaders.set('x-forwarded-for', clientIp);
    newHeaders.set('x-real-ip', clientIp);
  }

  const modifiedRequest = new Request(request, {
    headers: newHeaders,
  });

  // 4. Pass the modified request through to Umami
  const response = await context.next(modifiedRequest);
  
  if (isAllowedOrigin && origin) {
    response.headers.set('Access-Control-Allow-Origin', origin);
  }

  return response;
};
