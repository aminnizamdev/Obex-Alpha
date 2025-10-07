α‑T — Tokenomics Specification

Emission Schedule
- Total supply in μOBX; per‑slot payout uses accumulator arithmetic with halving periods.
- On each slot: acc_num += R0_NUM; payout = floor(acc_num / den(period)); credit emission; acc_num -= payout * den.
- At terminal slot: flush residual to hit exact total supply; assert total emitted equals TOTAL_SUPPLY_UOBX.

Fee Split (NLB)
- Epoch length NLB_EPOCH_SLOTS; on epoch roll: snapshot effective supply; compute split percents (verifier/treasury/burn) based on supply thresholds.
- Route fees with numerator/denominator (10k basis‑point scheme) and escrow cap; release cannot exceed escrow.

DRP (Distributed Reward Protocol)
- Baseline share evenly across participation set; lottery across K winners with unique indices derived from beacon draw H("obex.reward.draw", [ y_edge, LE(slot,8), LE(t,4) ]).
- Reward payout ordering by H("obex.reward.rank", [ y_edge, pk ]) ascending.

System Transactions & Ordering
- SysTx kinds: EscrowCredit, EmissionCredit, VerifierCredit, TreasuryCredit, Burn, RewardPayout.
- Canonical within‑slot ordering: Escrow → Emission → Verifier → Treasury → Burn → RewardPayout (where RewardPayouts are rank‑sorted).

Invariants
- Emission monotone; escrow conservation; splits respect escrow; burn reduces effective supply snapshot for next epoch.

Golden Artifacts (α‑T)
- Emission sampling traces; sys_tx golden encode/decode; ordering tests; fee‑split epoch roll cases.


