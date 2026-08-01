import { bytesToBase64, generateCredential, signDecision, type Decision } from './crypto';
import {
  isAwaiting,
  newAwaitingRequestIds,
  resolvingCopy,
  type Ask,
  type Caller,
  type SecretAsk,
  type WireQueueRow,
  type WireSnapshot,
} from './snapshot';
import { loadCredential, saveCredential, type StoredCredential } from './storage';

const IDLE_TITLE = 'secreq link';

export async function start(root: HTMLElement): Promise<void> {
  const token = decodeURIComponent(location.hash.slice(1));
  if (token) {
    renderPairing(root, token);
    return;
  }

  const credential = await loadCredential();
  if (credential === undefined) {
    renderUnpaired(root);
    return;
  }
  renderQueue(root, credential);
}

function renderPairing(root: HTMLElement, token: string): void {
  root.replaceChildren();
  const card = element('main', 'pairing-card');
  card.append(
    eyebrow('New device'),
    heading('Pair with this host'),
    paragraph(
      'This browser will create a device key that stays here. Give it a name you will recognize when reviewing or revoking devices.',
    ),
  );
  const form = element('form', 'pairing-form');
  const label = element('label');
  label.textContent = 'Device nickname';
  const input = document.createElement('input');
  input.name = 'nickname';
  input.required = true;
  input.maxLength = 64;
  input.autocomplete = 'off';
  input.placeholder = "Craig's iPhone";
  label.append(input);
  const submit = button('Pair device', 'primary');
  submit.type = 'submit';
  const status = element('p', 'form-status');
  status.setAttribute('role', 'status');
  form.append(label, submit, status);
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = 'Creating this device key…';
    void pair(token, input.value.trim())
      .then((credential) => {
        history.replaceState(null, '', '/');
        document.title = IDLE_TITLE;
        renderQueue(root, credential);
      })
      .catch((error: unknown) => {
        status.textContent = messageFrom(error);
        submit.disabled = false;
      });
  });
  card.append(form);
  root.append(card);
  input.focus();
}

async function pair(token: string, nickname: string): Promise<StoredCredential> {
  const keyPair = await generateCredential();
  const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const response = await fetch('/pair', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      token,
      nickname,
      public_key_b64: bytesToBase64(new Uint8Array(publicKey)),
    }),
  });
  if (!response.ok) {
    const detail = (await response.text()).trim();
    throw new Error(detail || 'This pairing link was refused. Run `secreq link` for a new one.');
  }

  const credential = { privateKey: keyPair.privateKey, nickname };
  await saveCredential(credential);
  return credential;
}

function renderUnpaired(root: HTMLElement): void {
  root.replaceChildren();
  const card = element('main', 'pairing-card');
  card.append(
    eyebrow('Not paired'),
    heading('Pair this browser first'),
    paragraph('Run `secreq link` at the host and scan the QR code with this device.'),
  );
  root.append(card);
}

function renderQueue(root: HTMLElement, credential: StoredCredential): void {
  root.replaceChildren();
  const shell = element('main', 'app-shell');
  const header = element('header', 'app-header');
  const titleGroup = element('div');
  titleGroup.append(eyebrow('Linked device'), heading('Pending requests'));
  const device = element('div', 'device-chip');
  device.textContent = credential.nickname;
  header.append(titleGroup, device);

  const banner = element('section', 'request-banner');
  banner.hidden = true;
  banner.setAttribute('role', 'alert');
  const bannerText = element('div');
  const bannerHeading = element('strong');
  bannerHeading.textContent = 'A request needs your decision';
  bannerText.append(bannerHeading, paragraph('Review what is asking before approving it.'));
  const dismiss = button('Dismiss', 'quiet');
  dismiss.addEventListener('click', () => (banner.hidden = true));
  banner.append(bannerText, dismiss);

  const connection = element('p', 'connection-status');
  connection.textContent = 'Connecting to the host…';
  const error = element('p', 'global-error');
  error.hidden = true;
  error.setAttribute('role', 'alert');
  const list = element('section', 'request-list');
  shell.append(header, banner, connection, error, list);
  root.append(shell);

  let currentRows: WireQueueRow[] = [];
  let currentError: WireSnapshot['link_error'];
  let flash: ReturnType<typeof window.setInterval> | undefined;
  let stopFlash: ReturnType<typeof window.setTimeout> | undefined;
  const events = new EventSource('/events');

  const draw = () => {
    error.hidden = currentError === undefined;
    error.textContent = currentError?.message ?? '';
    list.replaceChildren();
    if (currentRows.length === 0) {
      const empty = element('div', 'empty-state');
      empty.append(heading('Nothing waiting'), paragraph('Keep this page open for live requests.'));
      list.append(empty);
      return;
    }
    for (const row of currentRows) list.append(renderRow(row, credential));
  };

  events.addEventListener('open', () => {
    connection.textContent = 'Live with the host';
    connection.classList.add('connected');
  });
  events.addEventListener('error', () => {
    connection.textContent = 'Reconnecting to the host…';
    connection.classList.remove('connected');
  });
  events.addEventListener('message', (event) => {
    try {
      const snapshot = JSON.parse(event.data) as WireSnapshot;
      const arrivals = newAwaitingRequestIds(currentRows, snapshot.queue);
      currentRows = snapshot.queue;
      currentError = snapshot.link_error;
      draw();
      if (arrivals.length > 0) {
        banner.hidden = false;
        playChime();
        if (flash !== undefined) window.clearInterval(flash);
        if (stopFlash !== undefined) window.clearTimeout(stopFlash);
        let urgent = true;
        document.title = 'Approval needed · secreq';
        flash = window.setInterval(() => {
          urgent = !urgent;
          document.title = urgent ? 'Approval needed · secreq' : IDLE_TITLE;
        }, 700);
        stopFlash = window.setTimeout(() => {
          if (flash !== undefined) window.clearInterval(flash);
          flash = undefined;
          document.title = IDLE_TITLE;
        }, 12_000);
      }
    } catch {
      connection.textContent = 'The host sent an unreadable update; waiting for the next one…';
    }
  });
  window.setInterval(() => {
    for (const status of list.querySelectorAll<HTMLElement>('[data-resolving-request]')) {
      const row = currentRows.find(
        (candidate) => candidate.request_id === status.dataset.requestId,
      );
      if (row !== undefined) status.textContent = resolvingCopy(row);
    }
  }, 1_000);
  draw();
}

function renderRow(row: WireQueueRow, credential: StoredCredential): HTMLElement {
  const card = element('article', 'request-card');
  const top = element('div', 'request-top');
  const labels = element('div');
  const kind = element('span', 'request-kind');
  kind.textContent = kindLabel(row.representative);
  const command = element('h2');
  command.textContent = row.representative.command.join(' ');
  labels.append(kind, command);
  const status = element('span', isAwaiting(row) ? 'status awaiting' : 'status resolving');
  status.textContent = isAwaiting(row) ? 'Awaiting decision' : resolvingCopy(row);
  if (!isAwaiting(row)) status.dataset.resolvingRequest = row.request_id;
  top.append(labels, status);
  card.append(top, renderAsk(row.representative));

  if (isAwaiting(row)) {
    const actions = element('div', 'request-actions');
    const deny = button('Deny', 'danger');
    const approve = button('Approve', 'primary');
    const feedback = element('p', 'decision-status');
    feedback.setAttribute('role', 'status');
    const decide = (decision: Decision) => {
      deny.disabled = true;
      approve.disabled = true;
      feedback.textContent = decision === 'approve' ? 'Signing approval…' : 'Signing denial…';
      void submitDecision(row, credential.privateKey, decision).catch((error: unknown) => {
        feedback.textContent = messageFrom(error);
        deny.disabled = false;
        approve.disabled = false;
      });
    };
    deny.addEventListener('click', () => decide('deny'));
    approve.addEventListener('click', () => decide('approve'));
    actions.append(deny, approve, feedback);
    card.append(actions);
  }
  return card;
}

async function submitDecision(
  row: WireQueueRow,
  privateKey: CryptoKey,
  decision: Decision,
): Promise<void> {
  const payload = await signDecision(privateKey, {
    request_id: row.request_id,
    ask_hash_hex: row.ask_hash_hex,
    decision,
  });
  const response = await fetch('/decision', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    if (response.status === 403) {
      throw new Error('This device is no longer paired. Pair it again at the host.');
    }
    throw new Error(
      'The request changed or was already resolved. Waiting for the host to refresh…',
    );
  }
}

function renderAsk(ask: Ask): HTMLElement {
  const details = element('dl', 'request-details');
  addDetail(details, 'Wrap', ask.dedupe_key.wrap);
  const subject = ask.subject;
  if (subject.kind === 'wrap') {
    addDetail(details, 'In', subject.cwd);
    addCallers(details, subject.callers, subject.callers_truncated);
    for (const secret of subject.secrets) addSecret(details, secret);
  } else if (subject.kind === 'ssh_sign') {
    addDetail(details, 'In', subject.cwd);
    addDetail(details, 'Key', subject.info.key_id);
    addDetail(details, 'Fingerprint', subject.info.fingerprint);
    if (subject.info.reason) addDetail(details, 'Reason', subject.info.reason);
    if (subject.info.anchor) {
      addDetail(details, 'Session', `${subject.info.anchor.name} · ${subject.info.anchor.pid}`);
    }
    addCallers(details, subject.callers, subject.callers_truncated);
  } else {
    addDetail(details, 'Host scope', subject.scope);
    addDetail(details, 'Reference', subject.reference);
    if (subject.guest_chain)
      addDetail(details, 'Guest says', `${subject.guest_chain} · not verifiable`);
    if (subject.declared_by) {
      addDetail(details, 'Declared by', `${subject.declared_by.name} · ${subject.declared_by.pid}`);
    }
  }
  return details;
}

function addSecret(details: HTMLDListElement, secret: SecretAsk): void {
  const bits = [`${secret.provider}/${secret.locator}`];
  if (secret.description) bits.push(secret.description);
  if (secret.reason) bits.push(`Reason: ${secret.reason}`);
  if (secret.declared_as) bits.push(`Declared as ${secret.declared_as}`);
  if (secret.requested_by?.length) bits.push(`Requested by ${secret.requested_by.join(', ')}`);
  addDetail(details, `Secret · ${secret.name}`, bits.join(' · '));
}

function addCallers(details: HTMLDListElement, callers: Caller[], truncated = false): void {
  if (callers.length === 0) return;
  const chain = callers
    .map((caller) => `${caller.name} (${caller.pid}) · ${caller.command}`)
    .join(' ← ');
  addDetail(details, 'Asked by', truncated ? `${chain} ← …` : chain);
}

function addDetail(details: HTMLDListElement, label: string, value: string): void {
  if (!value) return;
  const term = document.createElement('dt');
  term.textContent = label;
  const description = document.createElement('dd');
  description.textContent = value;
  details.append(term, description);
}

function kindLabel(ask: Ask): string {
  switch (ask.subject.kind) {
    case 'wrap':
      return 'Secret request';
    case 'ssh_sign':
      return 'SSH signature';
    case 'scoped_agent':
      return 'Scoped agent';
  }
}

function playChime(): void {
  try {
    const AudioContextClass = window.AudioContext;
    const context = new AudioContextClass();
    const oscillator = context.createOscillator();
    const gain = context.createGain();
    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(660, context.currentTime);
    gain.gain.setValueAtTime(0.0001, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.13, context.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + 0.35);
    oscillator.connect(gain).connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.36);
    oscillator.addEventListener('ended', () => void context.close());
  } catch {
    // Mobile browsers can withhold audio until a gesture. The banner and
    // flashing title remain the dependable in-page signals.
  }
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

function heading(copy: string): HTMLHeadingElement {
  const node = element('h1');
  node.textContent = copy;
  return node;
}

function paragraph(copy: string): HTMLParagraphElement {
  const node = element('p');
  node.textContent = copy;
  return node;
}

function eyebrow(copy: string): HTMLParagraphElement {
  const node = element('p', 'eyebrow');
  node.textContent = copy;
  return node;
}

function button(copy: string, style: string): HTMLButtonElement {
  const node = element('button', `button ${style}`);
  node.type = 'button';
  node.textContent = copy;
  return node;
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong. Try again.';
}
