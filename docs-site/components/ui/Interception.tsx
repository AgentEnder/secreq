import { useState } from 'react';

/**
 * The hero's one moment: a command typed, caught, questioned, answered.
 *
 * This is a reconstruction of the real prompt window in HTML rather than a
 * screenshot, for two reasons — it has to animate, and it has to reflow on a
 * phone. Everything it shows matches fixture `02-single-pending`, which the
 * page also publishes further down as the real thing.
 *
 * The sequence is pure CSS (see `pages/interception.css`); React's only job
 * is to remount on replay, which restarts every animation at once without
 * touching a single timer.
 */
export function Interception() {
  const [run, setRun] = useState(0);

  return (
    <div className="icept" key={run}>
      <div className="icept-stage">
        <div className="icept-term-wrap">
          <div className="icept-term">
            <div className="icept-term-bar">
              <span>zsh</span>
              <span aria-hidden="true">·</span>
              <span>~/project</span>

              <button type="button" className="icept-replay" onClick={() => setRun((n) => n + 1)}>
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 16 16"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.9"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M14 8a6 6 0 1 1-1.8-4.3M14 2v4h-4" />
                </svg>
                Replay
              </button>
            </div>
            <div className="icept-term-body">
              <p className="icept-line">
                <span className="icept-sigil">$</span>
                <span className="icept-cmd">gh auth login</span>
              </p>
              <p className="icept-line icept-out">
                <span className="icept-sigil"> </span>
                <span>
                  GITHUB_TOKEN <span className="icept-mask">••••••••••••</span> released, masked
                </span>
              </p>
            </div>
          </div>
          <span className="icept-gate" aria-hidden="true" />
        </div>

        <div className="icept-ask-shell">
          <div className="icept-ask-clip">
            <div className="icept-ask">
              <p className="icept-ask-head">
                <b>gh</b> wants to use <b>GITHUB_TOKEN</b>
              </p>

              <div className="icept-well">
                <div className="icept-row" style={{ '--step': 0 } as React.CSSProperties}>
                  <span className="icept-key">Secret</span>
                  <span className="icept-val">
                    GITHUB_TOKEN <span className="dim">op://Personal/GitHub/credential</span>
                  </span>
                </div>

                <div className="icept-row" style={{ '--step': 1 } as React.CSSProperties}>
                  <span className="icept-key">Asked by</span>
                  <span className="chain">
                    <span className="chain-node" data-depth="0">
                      <span className="chain-name">zsh</span>
                      <span className="chain-pid">7926</span>
                    </span>
                    <span className="chain-node" data-depth="1" data-asker="true">
                      <span className="chain-name">gh</span>
                      <span className="chain-argv">gh auth login</span>
                    </span>
                  </span>
                </div>

                <div className="icept-row" style={{ '--step': 2 } as React.CSSProperties}>
                  <span className="icept-key">In</span>
                  <span className="icept-val">~/project</span>
                </div>
              </div>

              <div className="icept-actions">
                <span className="icept-btn">Deny</span>
                <span className="icept-btn icept-btn--approve">
                  Approve
                  <span className="icept-cursor" aria-hidden="true">
                    <svg viewBox="0 0 12 17" width="13" height="18" aria-hidden="true">
                      <path
                        d="M1 1.2 10.4 9.6 6.2 10.1 8.6 14.8 6.7 15.8 4.3 11.1 1 13.9z"
                        fill="currentColor"
                        stroke="var(--sq-panel)"
                        strokeWidth="1.1"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </span>
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
