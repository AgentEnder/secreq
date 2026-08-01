# Approve requests from a linked device

`secreq link` pairs a phone or tablet with the consent daemon over your
private LAN. The linked page shows the same pending request details as the
desktop prompt and can approve or deny them. It does not depend on a cloud
service, and the local prompt remains available throughout.

## Pair a device

Run this on the machine where secreq resolves your secrets:

```sh
secreq link
```

The command starts a 60-second, single-use enrollment window and prints a QR
code. Scan it in person from the device you want to pair, enter a nickname,
and keep the page as a bookmark or on your home screen.

::term{id=link-pair}

The daemon listens on port `46371` of the machine's private-LAN address. A
port collision or a default route that is not private makes pairing fail with
an error; it does not weaken or interrupt local consent.

The browser creates a software-managed P-256 signing key without Web Crypto,
because a plain-HTTP LAN page is not a secure context. It stores the private
key in IndexedDB. The host records only the public key and the nickname in
`~/.secreq/devices.json`.

Paired devices persist across daemon stops, restarts, and upgrades. When the
registry is nonempty, the daemon starts the LAN listener automatically. Keep
the linked page open when you want live requests: it receives updates through
an event stream. A backgrounded page may miss the sound or title flash;
background notifications are not part of this feature.

## Approve a request

The linked page starts empty and stays live with the host. When a request
arrives, it raises a banner and shows the command, working directory, caller
chain, secret reference, reason, and declaration provenance. Review those
details just as you would in the local prompt, then choose **Approve** or
**Deny**. The browser signs that decision with its device key; it never receives
the secret value.

::flow{screen=link-approval}

After the host accepts the signature, the card changes to **Resolving** while
the original provider completes, then leaves the queue. The local prompt stays
available for the entire flow. A decision made in either place resolves the
same pending request; the other surface observes the result rather than
granting a second approval.

## List and revoke devices

List the enrolled nicknames:

```sh
secreq link list
```

Revoke one by its exact nickname:

```sh
secreq link rm "Craig's iPhone"
```

Revocation takes effect before the command returns. A decision already in
flight from that device is refused because the daemon reloads the registry for
every signature check. Removing the final device also closes the LAN listener
immediately. Pair the device again to restore its authority; deleting the
browser bookmark alone does not revoke its key.

## Protections on the local network

This feature chooses LAN-only availability and signed decisions, not transport
confidentiality.

Someone on your Wi-Fi can observe which command, secret name, provider, and
locator a pending request names. Secret values and provider invocation
commands are never sent to the linked page. An ordinary LAN peer cannot forge
an approval or denial: each decision is signed by an enrolled P-256 key over
the request identity, the canonical request details, the decision, and a
single-use nonce. The browser recomputes the canonical request hash and
refuses to sign if it differs from the host's hash.

Plain HTTP does not authenticate the JavaScript delivered to the browser. An
active attacker who can alter LAN traffic can replace that JavaScript. The
replacement can extract or misuse the software-managed key and act as the
paired device. That attacker is outside this feature's accepted home-LAN
threat model. `secreq link` does not provide the channel authenticity of TLS,
WebAuthn, or a managed-device certificate.

The linked path is additive and fails closed. If the listener is unavailable,
the signature is bad, the request changed, or the device was revoked, the
request stays pending for the authoritative local prompt. Remote approval can
also leave a provider waiting for local interaction, such as a 1Password Touch
ID prompt on the host; the linked page reports a slow resolution, but the
provider's interaction still happens at the host.
