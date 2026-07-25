export function applyBaseUrl(
  href: string,
  baseUrl: string | undefined | null = import.meta.env.BASE_URL
): string {
  if (!baseUrl || baseUrl === '/' || baseUrl === './' || baseUrl === '.') {
    return href;
  }
  if (href.startsWith('http://') || href.startsWith('https://')) {
    return href;
  }
  const normalizedBaseUrl = baseUrl.endsWith('/') ? baseUrl : baseUrl + '/';
  const normalizedHref = href.startsWith('/') ? href.substring(1) : href;
  return normalizedBaseUrl + normalizedHref;
}
