"""Accessible, CSS-only SATARK intro overlay for the Streamlit shell."""
from __future__ import annotations

import streamlit as st


def render_intro_loader() -> None:
    """Show a short non-blocking intro using the parent document, without iframe scripting."""
    if st.session_state.get("_satark_intro_seen", False):
        return
    st.session_state["_satark_intro_seen"] = True
    st.markdown(
        """
        <style>
        #satark-intro-overlay {
          position:fixed; inset:0; z-index:2147483000; display:grid; place-items:center;
          padding:24px; box-sizing:border-box; pointer-events:none; overflow:hidden;
          color:#fff4df; text-align:center; font-family:ui-monospace,monospace;
          background:radial-gradient(ellipse at 50% 38%,rgba(126,61,177,.25),transparent 42%),
            radial-gradient(ellipse at 50% 100%,rgba(255,128,37,.13),transparent 45%),#10091e;
          animation:satark-intro-dismiss 1.7s ease .35s forwards;
        }
        #satark-intro-overlay::before {
          content:""; position:absolute; inset:0; opacity:.22; pointer-events:none;
          background-image:linear-gradient(rgba(255,255,255,.035) 1px,transparent 1px),
            linear-gradient(90deg,rgba(255,255,255,.035) 1px,transparent 1px);
          background-size:4px 4px;
        }
        #satark-intro-overlay .satark-intro-card { position:relative; width:min(460px,100%); }
        #satark-intro-overlay .satark-intro-mark {
          display:grid; place-items:center; width:76px; height:76px; margin:0 auto 18px;
          border:1px solid rgba(255,205,94,.7); border-radius:18px; color:#ffd36a;
          background:rgba(111,60,162,.28); box-shadow:0 0 34px rgba(255,173,62,.16);
          font-size:34px; font-weight:900;
        }
        #satark-intro-overlay .satark-intro-wordmark {
          color:#fff4d8; font-size:clamp(28px,6vw,38px); font-weight:900;
          letter-spacing:.2em; padding-left:.2em; text-shadow:3px 3px 0 #6e36a0;
        }
        #satark-intro-overlay .satark-intro-caption {
          margin-top:12px; color:#ffb24c; font-size:10px; font-weight:800;
          letter-spacing:.2em; text-transform:uppercase;
        }
        #satark-intro-overlay .satark-intro-status {
          margin-top:30px; color:#b9accb; font-size:10px; letter-spacing:.14em;
        }
        @keyframes satark-intro-dismiss {
          0% { opacity:1; visibility:visible; }
          78% { opacity:1; visibility:visible; }
          100% { opacity:0; visibility:hidden; }
        }
        @media(prefers-reduced-motion:reduce) {
          #satark-intro-overlay { animation-duration:.01ms; animation-delay:0s; }
        }
        </style>
        <div id="satark-intro-overlay" role="status" aria-label="SATARK readying workspace">
          <div class="satark-intro-card">
            <div class="satark-intro-mark" aria-hidden="true">S</div>
            <div class="satark-intro-wordmark">SATARK</div>
            <div class="satark-intro-caption">Pause · Inspect · Verify</div>
            <div class="satark-intro-status">SECURE WORKSPACE · READY</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
