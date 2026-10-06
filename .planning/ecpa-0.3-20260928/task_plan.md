# ECPA 0.3 iteration plan

1. Replace per-MOD host protocol probing with one versioned host capability
   snapshot while retaining a narrow absent-registry migration fallback.
2. Add manifest-declared scoped resource claims and reject incompatible MOD
   compositions before launch.
3. Preserve 0.2 parsing, lifecycle ownership, fail-closed compatibility, and
   compatibility freeze.
4. Validate Manager and vLLM-HUST independently, then exercise the paired
   clean-wheel host contract before merging both repositories.
5. Migrate one real plugin only after both base contracts merge.
