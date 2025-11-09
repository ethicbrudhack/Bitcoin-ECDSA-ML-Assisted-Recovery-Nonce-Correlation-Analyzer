# 🧠 Bitcoin ECDSA ML-Assisted Recovery & Nonce-Correlation Analyzer

> ⚠️ **Educational & Research Use Only**  
> This tool demonstrates the combination of **machine learning**, **statistical correlation**, and **ECDSA nonce reuse analysis**.  
> It is **not** intended to recover or exploit private keys belonging to others.  
> Use only on your own cryptographic data or with explicit written authorization.

---

## 🚀 Overview

This advanced Python-based analyzer combines **cryptographic analysis**, **machine learning (ML)**, and **nonce-correlation attacks** on the **Bitcoin secp256k1** curve.  
It reads weak signature data (e.g. from `vulnerabilities.txt`), detects correlated nonces, and continuously refines candidate keys (`k` and `d`) using adaptive search and regression models.

The system uses:
- **Heuristic nonce exploration**
- **Simulated annealing**
- **Hamming distance scoring**
- **Incremental machine learning (SGDRegressor)**
- **Automatic feature scaling**
- **Parallelized background correlation checks**

---

## ✨ Features

| Feature | Description |
|----------|--------------|
| 🧩 **Bech32 / Base58 decoding** | Full support for decoding Bitcoin addresses and witness programs |
| 🔍 **ECDSA correlation attack** | Detects nonce reuse or linear relationships between nonces |
| 🧮 **Machine Learning models** | Uses `SGDRegressor` to adaptively predict `k` and `d` candidates |
| 📊 **Correlation analysis** | Computes correlation coefficients among `(r, s, z)` signatures |
| 🎯 **Hamming & prefix scoring** | Ranks candidates by address similarity to a target |
| ⚡ **ThreadPoolExecutor support** | Parallel background analysis for better CPU utilization |
| 🧠 **Self-learning refinement** | Continuously improves prediction models based on outcomes |
| 🧱 **ML persistence (stubs)** | Placeholder model save functions for training checkpoints |
| 🔒 **Memory-safe iteration** | Adaptive cleanup and controlled CPU load |

---

## 📂 File Structure

| File | Description |
|------|-------------|
| `main.py` | Main script (this file) |
| `vulnerabilities.txt` | Input file containing signature pairs (r, s, z) suspected of nonce correlation |
| `ml_model.pkl`, `scaler.pkl` | (optional) Model files for saving ML state |
| `ml_k_model.pkl`, `ml_d_model.pkl` | Separate models for predicting `k` and `d` values |

---

## ⚙️ Configuration

| Variable | Description |
|-----------|--------------|
| `target_address` | Target Bech32 Bitcoin address to match |
| `memory_size` | Memory buffer size for caching signatures |
| `ml_update_interval` | Frequency (in iterations) of model retraining |
| `cpu_usage_target` | Approximate CPU load balancing goal |
| `HAMMING_THRESHOLD` | Distance threshold to trigger deep refinement |
| `current_search_range` | Initial search width for `k` exploration |
| `n` | Constant: secp256k1 order (2²⁵⁶ − 2³² − 977) |

**Dependencies**

pip install numpy sympy ecdsa scikit-learn base58


---

## 🧩 How It Works

### 1️⃣ Load Signatures  
Reads `vulnerabilities.txt` — each block contains two transactions with correlated nonces.  
Example entries include:


r1, s1, z1
r2, s2, z2
Ratio: ...


### 2️⃣ Decode & Parse  
Each line is parsed into structured dictionaries of integers.

### 3️⃣ Analyze Nonce Correlation  
Performs global correlation check between `(r, s, z)` values:
```python
corr_r_s, corr_r_z, corr_s_z = np.corrcoef(...)


Helps identify potential nonce dependency.

4️⃣ ML-Assisted Key Recovery

Two incremental SGDRegressor models (ml_k_model, ml_d_model) predict likely candidates for k and d.
Each iteration:

Generates candidate k values within adaptive range

Calculates candidate private keys d

Converts each to address

Computes Hamming distance and common prefix length with target address hash160

Updates models using the reward function reward = -hd/160

5️⃣ Refinement (Simulated Annealing)

Refines promising k values via small random perturbations and probabilistic acceptance — balancing exploration and exploitation.

6️⃣ Ratio-Based Attack

Periodically compares two correlated signatures (r1 == r2) to derive exact k and d using:

k = ((z1 - z2) * mod_inverse(s1 - s2, n)) mod n
d = ((s1 * k - z1) * mod_inverse(r1, n)) mod n

7️⃣ ML Model Update

Every few iterations, ML models are updated and correlation matrices recalculated in background threads.

🧠 Core Functions
Function	Purpose
bech32_decode() / bech32_encode()	Encode/decode Bech32 addresses
get_hash160_from_address()	Compute RIPEMD160(SHA256(pubkey)) hash
recover_d_cached()	Recover candidate private key (with caching)
compute_candidate_score()	Score candidate k via Hamming distance
refine_k()	Optimize k via simulated annealing
attack_using_ratios()	Execute ratio-based nonce correlation attack
analyze_all_signatures_correlations()	Compute Pearson correlation for r, s, z
check_correlation_ml()	Heuristic ML-based correlation detection
private_key_to_address()	Convert private key → compressed pubkey → Bech32 address
🧾 Example Console Output
==== Rozpoczynam analizę ataków na ECDSA ====
Docelowy adres: bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h
Wczytano 48 podpisów.
2025-11-09 12:12:21 - INFO - Iteracja 10: Wybrano k = 123456789 z Hamming distance = 22, wspólny prefiks = 8
Nie znaleziono klucza d, ponawiam próbę... Iteracja: 11
2025-11-09 12:12:33 - INFO - Zaktualizowano model ml_d_model (reward = -0.138)
🎉 ODNALAZŁEM POPRAWNE d! 🎉
Adres: bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h

⚡ Performance Tips

Reduce logging (logging.INFO → logging.WARNING) for speed.

Increase ml_update_interval for fewer retraining steps.

Limit search range or parallel threads if CPU throttles.

Save intermediate model states (placeholders included).

🔒 Ethical & Legal Notice

This code is for educational and research use only.
It demonstrates cryptographic weaknesses and ML-based key search concepts — not private key recovery or exploitation.

You must not:

Use it on addresses or data you don’t own.

Attempt to recover private keys from real users or blockchain data without permission.

You can:

Use it on synthetic or testnet signatures.

Study its ML-assisted search techniques.

Extend it for authorized security research.

🧰 Suggested Improvements

✅ Add persistence of ML model weights (pickle save/load).

✅ Implement GPU acceleration for batch scoring.

✅ Add visualization of correlation matrices and model convergence.

✅ Introduce CLI options (argparse) for delta ranges and verbosity.

✅ Integrate multiprocessing with adaptive batch size.

🪪 License

MIT License
© 2025 — Author: [Your Name or Alias]
Free for educational use and research, provided that no illegal or unethical activity is performed.

🧩 Summary

This project blends:

⚙️ Cryptography

🧮 Statistical correlation

🤖 Machine learning

🧠 Self-refinement heuristics

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
