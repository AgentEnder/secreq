import type { OnBeforePrerenderStartAsync } from 'vike/types';
import { DOC_SLUGS } from '../../../docs.nav';

/**
 * Prerender one static page per doc named in the nav manifest. Static GitHub
 * Pages has no server, so every `/docs/<slug>` route must be emitted at build
 * time (SSG).
 */
const onBeforePrerenderStart: OnBeforePrerenderStartAsync = async () =>
  DOC_SLUGS.map((slug) => `/docs/${slug}`);

export default onBeforePrerenderStart;
