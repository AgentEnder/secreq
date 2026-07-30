import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { SHOT_OPEN_EVENT, type ShotOpenDetail, type ShotScene } from './shot-events';

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
  source: HTMLImageElement;
  src: string;
  alt: string;
  caption: string;
  scene: ShotScene | null;
}

/**
 * What the viewer should morph out of, or back into.
 *
 * Normally the thumbnail is the render itself. Where a `<secreq-window>`
 * has rebuilt the window as DOM, the render is hidden, and a `display: none`
 * element captures nothing. The scene standing in its place is what the
 * reader can actually see, so that is what grows into the dialog's fresh
 * reconstruction.
 */
function morphSource(render: HTMLImageElement): HTMLElement {
  if (render.offsetParent !== null) return render;
  return render.closest('.shot-zoom')?.querySelector<HTMLElement>('.sqw-stage') ?? render;
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
        source,
        src: source.currentSrc || source.src,
        alt: source.alt,
        caption,
        scene: event.detail.scene,
      };

      clearTransitionNames();
      const morph = morphSource(source);
      morph.style.viewTransitionName = VT_NAME;
      withTransition(() => {
        morph.style.viewTransitionName = '';
        setShot(next);
      });
    };

    document.addEventListener(SHOT_OPEN_EVENT, onOpen);
    return () => document.removeEventListener(SHOT_OPEN_EVENT, onOpen);
  }, []);

  const close = useCallback(() => {
    // Morph back to whichever thumbnail this came from, if it is still on
    // screen — after a client-side navigation it may not be.
    const render = shot?.source.isConnected ? shot.source : undefined;
    const thumb = render && morphSource(render);

    withTransition(() => {
      if (thumb) thumb.style.viewTransitionName = VT_NAME;
      setShot(null);
    });
  }, [shot]);

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
          {shot.scene ? (
            <LightboxScene scene={shot.scene} alt={shot.alt} />
          ) : (
            <img src={shot.src} alt={shot.alt} />
          )}
          {shot.caption && <figcaption dangerouslySetInnerHTML={{ __html: shot.caption }} />}
        </figure>
      )}
    </dialog>,
    document.body,
  );
}

/**
 * Own and scale a scene inside the dialog.
 *
 * The scene arrives as real DOM because it can originate in a custom element
 * living inside raw markdown, outside React's tree. React owns only the stage;
 * this effect places the fresh draw inside it and keeps the same `--sqw-scale`
 * contract the inline window uses.
 */
function LightboxScene({ scene, alt }: { scene: ShotScene; alt: string }) {
  const stageRef = useRef<HTMLDivElement>(null);
  const [width, height] = scene.size;
  // The committed render is rasterised at 2× the captured point size. Let
  // the reconstruction grow to the same ceiling: capping it at `width`
  // made a 500pt prompt shrink when its landing-page column was already
  // wider than 500px. The viewport terms remain the real limits on a
  // smaller screen.
  const renderWidth = width * 2;

  useEffect(() => {
    const stage = stageRef.current;
    if (!stage) return;
    stage.replaceChildren(scene.element);
    const rescale = () => {
      const scale = stage.clientWidth / width;
      // Child effects run before the parent calls `showModal()`. A closed
      // dialog measures zero wide, and writing that transient measurement
      // makes the scene disappear from the view-transition snapshot.
      if (scale > 0) scene.element.style.setProperty('--sqw-scale', String(scale));
    };
    const resize = new ResizeObserver(rescale);
    resize.observe(stage);
    rescale();
    return () => resize.disconnect();
  }, [scene, width]);

  return (
    <div
      ref={stageRef}
      className="sqw-stage sqw-lightbox-stage"
      role="group"
      aria-label={alt}
      style={{
        aspectRatio: `${width} / ${height}`,
        width: `min(${renderWidth}px, 96vw, ${(82 * width) / height}dvh)`,
        maxWidth: '100%',
      }}
    />
  );
}
