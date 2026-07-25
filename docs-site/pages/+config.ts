import vikeReact from 'vike-react/config';
import type { Config } from 'vike/types';

export default {
  title: 'secreq',
  description:
    '1Password Shell Plugins, but generic — wrap the CLIs you use every day so each invocation gets its credentials from your secret store, with provenance-aware consent and output masking.',
  prerender: true,
  passToClient: ['navigation'],
  extends: [vikeReact],
} satisfies Config;
