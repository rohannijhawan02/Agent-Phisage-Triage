# Public email data for a benchmark

No public corpus is bundled or automatically downloaded. Curate a reviewed manifest before fitting a probability model; the five repository samples are only smoke examples. Preserve each source's terms and do not treat a balanced research set as the prevalence of a live inbox.

| Source | Useful role | Limitation to record |
| --- | --- | --- |
| [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) | Raw `.eml` phishing examples | Phishing-only source; review labels, collection period, and repeated campaigns. |
| [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | Raw ham and spam for parser and baseline checks | Mostly early-2000s mail; modern legitimate alerts need a separate slice. Spam is not automatically phishing. |
| [Enron Email Dataset](https://www.cs.cmu.edu/~enron/) | Legitimate business correspondence and sender-context examples | Old and privacy-sensitive; attachments are absent, and there are no modern BEC attack labels. |
| [MeAJOR](https://arxiv.org/abs/2507.17978) | Multi-source benchmark design and traditional baselines | Check available format and provenance; engineered rows may lack complete MIME evidence. |
| Analyst-reviewed modern benign exports | Current password notices, invoices, alerts, and newsletters | Require collection permission; keep raw private mail outside this repository. |

For every imported email, record `source`, collection `date` if known, original label, normalized binary phishing label, campaign/domain `group`, split, and slices such as `bec`, `credential_phishing`, `html_link`, `suspicious_attachment`, `spam`, and `modern_benign`. Manually inspect label conflicts and near duplicates. Keep one campaign or sender-domain group entirely within one partition. Reserve a locked test slice from different periods or sources when possible. Use a separate modern benign slice so ordinary account notices and newsletters do not appear phishing merely because they contain security vocabulary.

Run `triage.py prepare` on the resulting manifest. It writes one feature record per message and retains the source metadata and MIME completeness flag. The `fit` command rejects duplicate hashes and groups crossing partitions. Re-run `prepare` with each candidate LLM; do not compare candidate scores obtained from an incumbent model's feature file.

When `--memory-file` is used, each case needs a timezone-aware `confirmed_at`; each manifest email needs a defensible message-time `date`, not a later export date. Preparation retrieves only cases confirmed before that cutoff. For a stronger temporal benchmark, freeze the intelligence and memory snapshots before the locked test period and audit campaign identifiers across partitions as well as the code's hash/content/group and exact URL/attachment-hash checks. Do not use analyst confirmations derived from test labels as earlier-case context.
