import { withApiPackage } from 'vike-plugin-typedoc/server';
import type { PageContextServer } from 'vike/types';

/** The single documented SDK package (its `.typedoc/<slug>.json` basename). */
const PACKAGE_SLUG = 'secreq-rule';

export function data(pageContext: PageContextServer) {
  return withApiPackage(pageContext, PACKAGE_SLUG);
}

export type ApiPackageData = ReturnType<typeof data>;
