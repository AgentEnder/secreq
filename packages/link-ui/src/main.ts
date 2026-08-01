import './style.css';
import { start } from './app';

const root = document.querySelector<HTMLElement>('#app');
if (root === null) throw new Error('missing #app');

void start(root).catch((error: unknown) => {
  const message = document.createElement('p');
  message.className = 'fatal-error';
  message.textContent = error instanceof Error ? error.message : 'Unable to start secreq link.';
  root.replaceChildren(message);
});
