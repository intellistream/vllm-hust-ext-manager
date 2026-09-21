# Finite exposure-transaction model

This artifact exhausts the declared finite abstraction of the ECPA exposure
transaction. It enumerates every reachable state and every action from each
state until a fixed point, checking admission, intent/receipt, predecessor,
fail-closed, safety-unknown, and strong-rollback invariants.

```bash
python3 experiments/transaction_model/explore.py --check
python3 -m pytest -q tests/test_transaction_model.py
```

The result is `exhaustive-finite-abstract-model`, not a formal-real experiment,
a proof about arbitrary implementations, or a production recovery result. Its
assumptions are part of the generated artifact. The real vLLM-HUST adapter,
authority-owned observations, and injected recovery cells remain necessary for
H3.
