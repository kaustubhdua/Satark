#!/usr/bin/env python3
"""Golden scores from the Python reference so the JS inference (web/src/lib/learned-models.mjs) can be
checked against it. Regenerate:  python scripts/generate_model_parity_fixture.py"""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ml import train_url_model as U, train_message_model as M, train_pdf_model as P, train_image_model as I  # noqa: E402
from ml.train_email_model import email_text  # noqa: E402

HOSTS = ["google.com", "paypal.com", "github.com", "paypa1-secure-login.000webhostapp.com", "secure-update-account.xyz",
         "login-microsoftonline.verify-id.top", "192.168.1.10", "203.0.113.7", "a.b.c.d.e.f.g.example.org", "xn--80ak6aa92e.com",
         "x", "my-bank-0000000-verify.example.co.uk", "ex_ample.com", "a" * 60 + ".net"]
MESSAGES = ["Hey, lunch at noon?", "WINNER! You have won a £1000 prize. Call 09061701461 now to claim",
            "Your account is suspended. Verify your password now", "FREE entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry",
            "Ok lar... Joking wif u oni...", "URGENT! Your mobile No. was awarded $2000 Bonus Caller Prize", "名前 😀 Prize now £50 www.claim.example",
            "İstanbul K‌elvin ŉ test 12345 free", "SHOUTING TEXT IN CAPITALS ONLY", "", "   ", "a" * 500, "Call now http://x.example/win 50p per min"]
LONG = ["Dear customer, your mailbox quota is almost full. " * 12 + "Click the link to verify your password immediately or your account will be closed.",
        "Hi team, attaching the minutes from Tuesday's planning meeting. Please review the action items and reply with corrections by Friday. " * 4,
        "名前 😀 " + "Urgent prize winner claim now! " * 40, "x" * 3500]


def band(model, s):
    return "high" if s >= model["thresholds"]["high"] else "elevated" if s >= model["thresholds"]["elevated"] else "low"


def build():
    um = json.loads((ROOT / "ml/models/url-host-v1.json").read_text())
    mm = json.loads((ROOT / "ml/models/message-v1.json").read_text())
    hosts, msgs = [], []
    for h in HOSTS:
        s = um["bias"] + sum(um["weights"].get(t, 0.0) for t in U.feature_tokens(U.doc(h)))
        hosts.append({"host": h, "score": s, "band": band(um, s)})
    em = json.loads((ROOT / "ml/models/email-v1.json").read_text())
    for m in MESSAGES + LONG:
        t = m.strip()
        if len(t) >= 300:  # routing rule mirrored in learned-models.mjs (EMBER_MIN_CHARS -> EMAIL_MIN_CHARS)
            mod, name = em, "email"
            text = t[: em["max_chars"]]
        else:
            mod, name, text = mm, "message", m
        s = mod["bias"] + sum(mod["weights"].get(t_, 0.0) for t_ in M.feature_tokens(text))
        msgs.append({"text": m, "model": name, "score": s, "band": band(mod, s)})
    pm = json.loads((ROOT / "ml/models/pdf-v1.json").read_text())
    pdf_cases = [
        {"pdfsizeKb": 12.0, "pages": 1, "isEncrypted": 0, "obj": 14, "endobj": 14, "stream": 3, "endstream": 3, "xref": 1, "trailer": 1, "startxref": 1, "objstm": 0, "js": 1, "javascript": 1, "aa": 0, "openaction": 1, "acroform": 0, "jbig2": 0, "richmedia": 0, "launch": 0, "embeddedfile": 0, "xfa": 0},
        {"pdfsizeKb": 120.0, "pages": 5, "isEncrypted": 0, "obj": 45, "endobj": 45, "stream": 12, "endstream": 12, "xref": 1, "trailer": 1, "startxref": 1, "objstm": 0, "js": 0, "javascript": 0, "aa": 0, "openaction": 0, "acroform": 0, "jbig2": 0, "richmedia": 0, "launch": 0, "embeddedfile": 0, "xfa": 0},
    ]
    pdfs = []
    for c in pdf_cases:
        toks = P.pdf_tokens_from_features(
            c["pdfsizeKb"], c["pages"], c["isEncrypted"], c["obj"], c["endobj"],
            c["stream"], c["endstream"], c["xref"], c["trailer"], c["startxref"],
            c["objstm"], c["js"], c["javascript"], c["aa"], c["openaction"],
            c["acroform"], c["jbig2"], c["richmedia"], c["launch"], c["embeddedfile"], c["xfa"],
        )
        s = pm["bias"] + sum(pm["weights"].get(t_, 0.0) for t_ in toks)
        pdfs.append({"stats": c, "score": s, "band": band(pm, s)})
    im = json.loads((ROOT / "ml/models/image-v1.json").read_text())
    img_cases = [
        {"width": 1024, "height": 1024, "elaMean": 2.1, "elaStd": 2.4, "elaHighRatio": 0.01, "lapMean": 10.0, "lapStd": 12.0, "flatRatio": 0.35, "satMean": 0.45},
        {"width": 1920, "height": 1080, "elaMean": 6.5, "elaStd": 7.0, "elaHighRatio": 0.12, "lapMean": 28.0, "lapStd": 35.0, "flatRatio": 0.12, "satMean": 0.25},
    ]
    images = []
    for c in img_cases:
        toks = I.extract_image_tokens(
            c["width"], c["height"], c["elaMean"], c["elaStd"], c["elaHighRatio"],
            c["lapMean"], c["lapStd"], c["flatRatio"], c["satMean"],
        )
        s = im["bias"] + sum(im["weights"].get(t_, 0.0) for t_ in toks)
        images.append({"stats": c, "score": s, "band": band(im, s)})
    return {"hosts": hosts, "messages": msgs, "pdfs": pdfs, "images": images}


if __name__ == "__main__":
    out = ROOT / "web/tests/fixtures/model-parity.json"
    out.write_text(json.dumps(build(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", out.relative_to(ROOT))
