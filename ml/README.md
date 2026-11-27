# Model training

```bash
python -m venv .venv && . .venv/bin/activate && pip install scikit-learn numpy scipy
curl -L -o phish.txt https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt
curl -L -o top.txt   https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains
curl -L -o sms.tsv   https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv
python ml/train_url_model.py     --phish phish.txt --benign top.txt
python ml/train_message_model.py --data sms.tsv
cp ml/models/*.json web/src/lib/models/
python scripts/generate_model_parity_fixture.py
```

Datasets are never committed. Output models record the SHA-256 of the exact input files. See `docs/MODEL_CARDS.md`.
The phishing list changes daily, so retraining yields slightly different numbers.
