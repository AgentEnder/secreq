import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { SHOT_OPEN_EVENT, type ShotOpenDetail } from './shot-events';

/**
 * The full-size viewer, rendered once for the whole app.
 *
 * Mounted in the layout and portalled to `<body>`, so it escapes the
 * documentation column's stacking and width without any element on the
 * page having to know it exists. Screenshots ask for it by dispatching
 * `secreq:shot-open`, which bubbles here from anywhere — including the
 * server-rendered figures markdown injects as raw HTML, which React never
 * gets to own.
 *
 * The dialog's open state is **derived from React state and reconciled in
 * an effect**, not toggled at the call site. That is the fix for a viewer
 * that used to intermittently do nothing when clicked: the old version
 * called `showModal()` inside a view-transition callback, so a transition
 * that got skipped or threw took the dialog with it — and a `close()` lost
 * the same way left the dialog open, which made the *next* `showModal()`
 * throw. Reconciling means every render drives the DOM back to whatever
 * the state says, so a dropped animation costs an animation and nothing
 * else.
 */

const VT_NAME = 'shot-zoom';

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function canViewTransition(): boolean {
  return typeof document.startViewTransition === 'function' && !prefersReducedMotion();
}

/**
 * Drop `view-transition-name` from anything still carrying it.
 *
 * Two elements sharing a name makes the *next* transition fail, so an
 * interrupted open or close must not leave one behind.
 */
function clearTransitionNames(): void {
  document.querySelectorAll<HTMLElement>(`[style*="${VT_NAME}"]`).forEach((node) => {
    node.style.viewTransitionName = '';
  });
}

/**
 * Run `mutate` inside a view transition where possible, plainly where not.
 *
 * The transition is decoration; the mutation is the point. Every failure
 * path — unsupported, skipped, thrown — still runs the mutation exactly
 * once.
 */
function withTransition(mutate: () => void): void {
  if (!canViewTransition()) {
    mutate();
    return;
  }

  let ran = false;
  const once = () => {
    if (ran) return;
    ran = true;
    mutate();
  };

  try {
    const transition = document.startViewTransition(once);
    transition.finished.catch(() => {}).finally(clearTransitionNames);
    transition.updateCallbackDone.catch(() => once());
  } catch {
    once();
  }
}

interface Shot {
  src: string;
  alt: string;
  caption: string;
}

export function ShotLightbox() {
  const [shot, setShot] = useState<Shot | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [mounted, setMounted] = useState(false);

  // Portals need a DOM target, which does not exist during pre-render.
  useEffect(() => setMounted(true), []);

  // The reconcile: state is the truth, the dialog follows it. Both calls
  // are guarded, so re-running this effect can never throw.
  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    if (shot && !el.open) el.showModal();
    if (!shot && el.open) el.close();
  }, [shot]);

  useEffect(() => {
    const onOpen = (event: CustomEvent<ShotOpenDetail>) => {
      const { source, caption } = event.detail;
      const next: Shot = {
        src: source.currentSrc || source.src,
        alt: source.alt,
        caption,
      };

      clearTransitionNames();
      source.style.viewTransitionName = VT_NAME;
      withTransition(() => {
        source.style.viewTransitionName = '';
        setShot(next);
      });
    };

    document.addEventListener(SHOT_OPEN_EVENT, onOpen);
    return () => document.removeEventListener(SHOT_OPEN_EVENT, onOpen);
  }, []);

  const close = useCallback(() => {
    // Morph back to whichever thumbnail this came from, if it is still on
    // screen — after a client-side navigation it may not be.
    const src = dialogRef.current?.querySelector('img')?.src;
    const thumb = [...document.querySelectorAll<HTMLImageElement>('.shot-img')].find(
      (candidate) => candidate.src === src && candidate.offsetParent !== null,
    );

    withTransition(() => {
      if (thumb) thumb.style.viewTransitionName = VT_NAME;
      setShot(null);
    });
  }, []);

  if (!mounted) return null;

  return createPortal(
    <dialog
      ref={dialogRef}
      className="shot-lightbox"
      // Anything outside the figure is backdrop.
      onClick={(event) => {
        if (!(event.target as HTMLElement).closest('figure')) close();
      }}
      // Escape: take it over so closing always runs the same path.
      onCancel={(event) => {
        event.preventDefault();
        close();
      }}
    >
      {shot && (
        <figure style={{ margin: 0 }}>
          <img src={shot.src} alt={shot.alt} />
          {shot.caption && <figcaption dangerouslySetInnerHTML={{ __html: shot.caption }} />}
        </figure>
      )}
    </dialog>,
    document.body,
  );
}
