# Sanitized bench evidence

These JSON records preserve the measurements and bounded observations needed to support the public claims. They omit device addresses, transient serial-port names, physical sticker labels, local paths, personal information, and private task identifiers.

The September 8 and September 11 records combine user-performed or user-observed hardware actions with captured serial output and tool-produced build checks. The September 14 record is derived from the completed dual-serial capture and its verified byte journal. Source hashes identify recorded checkout inputs; they do not independently prove the bytes loaded in flash unless the dated record says so.

Run `python verify_results.py` to recompute aggregate timing values.
