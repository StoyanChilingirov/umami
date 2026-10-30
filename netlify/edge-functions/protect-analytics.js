export default async (request, context) => {
  // Only inspect analytics tracking payloads
  if (request.url.includes('/api/send')) {
    const origin = request.headers.get('origin');
    const referer = request.headers.get('referer');

    // List of your actual production/allowed domains
    const allowedDomains = [
      'https://webabout.co.uk',
      'https://wonderful-sable-e155ef.netlify.app/' // Replace with your live Netlify URL
    ];

    // Check if origin or referer matches an allowed domain
    const isValidOrigin = allowedDomains.some(d => origin?.startsWith(d));
    const isValidReferer = allowedDomains.some(d => referer?.startsWith(d));

    // If it's opened locally (file://), via desktop, or from a rogue domain, block it!
    if (!isValidOrigin && !isValidReferer) {
      return new Response(JSON.stringify({ error: 'Forbidden: Unauthorized origin' }), {
        status: 403,
        headers: { 'content-type': 'application/json' },
      });
    }
  }

  return context.next();
};
