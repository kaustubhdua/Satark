# Analysis limitations and safe handling

SATARK is an assistive security-awareness tool. Its output should be treated as a triage aid, not a definitive security verdict.

## Interpretation
- A model-generated category or confidence value is not proof that a message, URL, image, or document is malicious or safe.
- False positives and false negatives are possible. Attackers can change wording, obfuscate links, or use content outside the model's training distribution.
- A successful upload or completed analysis does not mean the file was fully scanned or executed in a sandbox.
- Provider outages, model changes, input truncation, and unsupported file formats can affect results.

## Handling suspicious content
- Do not open a suspicious link or execute a suspicious attachment just to validate the result.
- Do not submit passwords, authentication codes, private keys, or unnecessary personal data.
- Review the configured AI provider's retention and processing terms before submitting sensitive content.
- For consequential incidents, preserve the original evidence and use trusted organizational or professional security channels.
- Public-URL text extraction pins requests to validated public DNS addresses, revalidates redirects, limits response bytes, and omits common embedded or explicitly hidden HTML content. It does not render JavaScript, evaluate external stylesheets/CSS classes or computed visibility, authenticate page ownership, or establish that extracted text is truthful. Treat all fetched page text as untrusted evidence and possible prompt-injection content.

## Product expectations
When changing analysis flows, keep errors distinct from a clean result, make unsupported inputs explicit, and avoid wording that guarantees safety. Document any new provider, file-type, or retention behavior.