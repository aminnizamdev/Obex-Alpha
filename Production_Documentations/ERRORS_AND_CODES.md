Stable Errors and Numeric Codes

Purpose
- Provide stable, loggable codes for reject reasons to aid interoperability and debugging.

HeaderReject (α‑II)
- 100 VersionMismatch
- 101 BadParentLink
- 102 BadSlot
- 103 VdfPiTooBig
- 104 VdfEllTooBig
- 105 BadSeedCommit
- 106 BeaconInvalid
- 107 TicketRootMismatch
- 108 PartRootMismatch
- 109 TxRootPrevMismatch

AlphaIReject (α‑I)
- 200 VersionMismatch
- 201 SlotMismatch
- 202 ChallengesLen
- 203 AlphaMismatch
- 204 VrfVerifyFailed
- 205 VrfOutputMismatch
- 206 SeedMismatch
- 207 SigInvalid
- 208 ChalIndexMismatch
- 209 ChalIndexBounds
- 210 JOrKOutOfRange
- 211 MerkleLiInvalid
- 212 MerkleLim1Invalid
- 213 MerkleLjInvalid
- 214 MerkleLkInvalid
- 215 LabelEquationMismatch
- 216 Oversize

AdmissionReject (α‑III)
- 300 BadSig
- 301 WrongSlot
- 302 WrongBeacon
- 303 NonceMismatch
- 304 BelowMinAmount
- 305 FeeMismatch
- 306 InsufficientFunds

Logging Guidance
- Log `{ code, reason, slot, header_id?, txid?, pk? }` as structured JSON; never include private keys or secrets.


