export { SectionHeader } from './SectionHeader';
export { InstallTabs } from './InstallTabs';
export type { InstallMethod } from './InstallTabs';
export { Interception } from './Interception';
export { Shot } from './Shot';
export { ShotLightbox } from './ShotLightbox';
export { Term } from './Term';

// Side-effect imports: register the custom elements, so the screenshots and
// sessions that markdown injects as raw HTML are upgraded too. There is no
// hydrate call to make — importing the definitions is the integration.
import './secreq-shot';
import './secreq-terminal';
