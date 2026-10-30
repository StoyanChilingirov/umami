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

  if (request.method === 'OPTIONS') {
    if (isAllowedOrigin) {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }
    return new Response('Forbidden', { status: 403 });
  }

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

  // --- PASS THROUGH WITH GEO/IP PRESERVATION ---
  const response = await context.next();
  
  if (isAllowedOrigin && origin) {
    response.headers.set('Access-Control-Allow-Origin', origin);
  }

  return response;
};
