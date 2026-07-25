import { withApiExport } from 'vike-plugin-typedoc/server';
import type { PageContextServer } from 'vike/types';

/** The single documented SDK package (its `.typedoc/<slug>.json` basename). */
const PACKAGE_SLUG = 'secreq-rule';

export function data(pageContext: PageContextServer) {
  const { symbol } = pageContext.routeParams;
  return withApiExport(pageContext, PACKAGE_SLUG, symbol);
}

export type SymbolDetailData = ReturnType<typeof data>;
