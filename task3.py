from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

PKG_PARAMS = {
    "p": 1004162036461488639338597000466705179253226703,
    "q": 950133741151267522116252385927940618264103623,
    "e": 973028207197278907211,
}

# Procurement Officer's RSA keys. Used to encrypt the result so that only
# the officer can decrypt it.
OFFICER_PARAMS = {
    "p": 1080954735722463992988394149602856332100628417,
    "q": 1158106283320086444890911863299879973542293243,
    "e": 106506253943651610547613,
}

# Inventory identities
INVENTORY_IDENTITIES: Dict[str, int] = {
    "A": 126,
    "B": 127,
    "C": 128,
    "D": 129,
}

# Per-signer random nonces (r_k) used in the Harn commitment phase.
INVENTORY_RANDOMS: Dict[str, int] = {
    "A": 621,
    "B": 721,
    "C": 821,
    "D": 921,
}

# Initial inventory records 
INITIAL_RECORDS = [
    {"item_id": "001", "quantity": 32, "price": 12, "location": "D"},
    {"item_id": "002", "quantity": 20, "price": 14, "location": "C"},
    {"item_id": "003", "quantity": 22, "price": 16, "location": "B"},
    {"item_id": "004", "quantity": 12, "price": 18, "location": "A"},
]


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDER = os.path.join(SCRIPT_DIR, "data")

def hash_to_int(*parts) -> int:
    joined = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(joined.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


# PRIVATE KEY GENERATOR (PKG)
@dataclass
class PKG:
    p: int
    q: int
    e: int
    n: int = field(init=False)
    phi: int = field(init=False)
    d: int = field(init=False)

    def __post_init__(self) -> None:
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        # d is the modular inverse of e mod phi(n): d * e === 1 (mod phi)
        self.d = pow(self.e, -1, self.phi)

    def public_key(self) -> Tuple[int, int]:
        #The PKG's public key (e, n) used for verification by all parties.
        return self.e, self.n

    def issue_secret_key(self, identity: int) -> int:
        return pow(identity, self.d, self.n)


@dataclass
class ProcurementOfficer:
    p: int
    q: int
    e: int
    n: int = field(init=False)
    phi: int = field(init=False)
    d: int = field(init=False)

    def __post_init__(self) -> None:
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def public_key(self) -> Tuple[int, int]:
        return self.e, self.n

    def decrypt(self, ciphertext: int) -> int:
        """RSA decryption with the officer's private key: m = c^d mod n."""
        return pow(ciphertext, self.d, self.n)



@dataclass
class HarnInventoryNode:
    node_id: str
    identity: int
    random_nonce: int
    secret_key: int       # g_k, issued by the PKG
    pkg_e: int            # shared public exponent
    pkg_n: int            # shared modulus

    def lookup_quantity(self, item_id: str, db: List[dict]) -> int:
        """Search this node's local DB for item_id and return its quantity."""
        for record in db:
            if record.get("item_id") == item_id:
                return record["quantity"]
        raise KeyError(f"Item {item_id} not found in inventory {self.node_id}")

    # Phase 1: commitment 
    def compute_commitment(self) -> int:
        return pow(self.random_nonce, self.pkg_e, self.pkg_n)

    # Phase 2: partial signature 
    def compute_partial_signature(self, t_aggregate: int, message: int) -> int:
        h = hash_to_int(t_aggregate, message)
        return (self.secret_key * pow(self.random_nonce, h, self.pkg_n)) % self.pkg_n

    # Phase 3: each node independently aggregates 
    @staticmethod
    def aggregate_commitments(t_values: List[int], pkg_n: int) -> int:
        product = 1
        for tk in t_values:
            product = (product * tk) % pkg_n
        return product

    @staticmethod
    def aggregate_partial_signatures(s_values: List[int], pkg_n: int) -> int:
        
        # s = s_1 * s_2 * ... * s_n  mod n 
        product = 1
        for sk in s_values:
            product = (product * sk) % pkg_n
        return product


# RSA ENCRYPTION
def rsa_encrypt(message: int, e: int, n: int) -> int:
    # RSA encryption with receiver's public key: c = m^e mod n.
    if message >= n:
        raise ValueError(
            f"Message {message} >= modulus n. RSA requires m < n. "
            "For a real system, hybrid encryption (RSA + AES) would be used."
        )
    return pow(message, e, n)


# HARN MULTI-SIGNATURE VERIFICATION
def verify_harn_multisignature(
    t: int,
    s: int,
    message: int,
    identities: List[int],
    pkg_e: int,
    pkg_n: int,
) -> Tuple[bool, int, int]:
    # Left-hand side: s^e mod n
    lhs = pow(s, pkg_e, pkg_n)

    # Right-hand side: (prod of identities) * t^H(t,m) mod n
    identity_product = 1
    for i in identities:
        identity_product = (identity_product * i) % pkg_n
    h = hash_to_int(t, message)
    rhs = (identity_product * pow(t, h, pkg_n)) % pkg_n

    return lhs == rhs, lhs, rhs


# CONSENSUS CHECK ON THE AGGREGATED SIGNATURE
def consensus_check_on_aggregates(
    per_node_aggregates: Dict[str, Tuple[int, int]]
) -> Tuple[bool, Tuple[int, int]]:
    values = list(per_node_aggregates.values())
    canonical = values[0]
    all_agree = all(v == canonical for v in values)
    return all_agree, canonical


# LOCAL DATABASE BOOTSTRAP
def bootstrap_inventory_databases() -> Dict[str, List[dict]]:
    os.makedirs(DATA_FOLDER, exist_ok=True)
    db: Dict[str, List[dict]] = {}

    for node_id in INVENTORY_IDENTITIES.keys():
        path = os.path.join(DATA_FOLDER, f"inventory_{node_id}.json")

        records: List[dict] = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Only keep entries that already look like Figure-1 records
                # so this works even if older files used a different schema.
                if isinstance(loaded, list):
                    records = [
                        r for r in loaded
                        if isinstance(r, dict) and "item_id" in r and "quantity" in r
                    ]
            except json.JSONDecodeError:
                records = []

        # If we couldn't load valid Figure-1-shaped records, seed the file
        # from the canonical INITIAL_RECORDS so the demo still runs.
        if not records:
            records = [dict(r) for r in INITIAL_RECORDS]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)

        db[node_id] = records

    return db



# QUERY WORKFLOW
def run_secure_query(item_id: str) -> None:
    print("=" * 72)
    print("TASK 3 - SECURE RECORD RETRIEVAL")
    print("=" * 72)

    # System setup: PKG, Officer, and the four inventory nodes
    print("\n[STEP 1] SYSTEM SETUP")
    print("-" * 72)

    pkg = PKG(**PKG_PARAMS)
    officer = ProcurementOfficer(**OFFICER_PARAMS)
    db = bootstrap_inventory_databases()

    print("PKG RSA parameters:")
    print(f"  p   = {pkg.p}")
    print(f"  q   = {pkg.q}")
    print(f"  n   = {pkg.n}")
    print(f"  phi = {pkg.phi}")
    print(f"  e   = {pkg.e}")
    print(f"  d   = {pkg.d}")

    print("\nProcurement Officer RSA parameters:")
    print(f"  n_officer = {officer.n}")
    print(f"  e_officer = {officer.e}")
    print(f"  d_officer = {officer.d}  (kept secret by Officer)")

    print("\nIssuing identity-based secret keys to each inventory node")
    print("(g_k = id_k ^ d mod n):")
    nodes: Dict[str, HarnInventoryNode] = {}
    for node_id, identity in INVENTORY_IDENTITIES.items():
        g_k = pkg.issue_secret_key(identity)
        nodes[node_id] = HarnInventoryNode(
            node_id=node_id,
            identity=identity,
            random_nonce=INVENTORY_RANDOMS[node_id],
            secret_key=g_k,
            pkg_e=pkg.e,
            pkg_n=pkg.n,
        )
        print(f"  Inventory {node_id}: id={identity}, r={INVENTORY_RANDOMS[node_id]}, "
              f"g_{node_id} = {g_k}")

    # Officer submits the query; PKG forwards to all nodes
    print("\n[STEP 2] QUERY SUBMISSION")
    print("-" * 72)
    print(f"Officer -> PKG: 'What is the quantity of item {item_id}?'")
    print(f"PKG -> Inventory A, B, C, D: forwarding query for item {item_id}")

    # Each node looks up the item locally and reports its quantity
    print("\n[STEP 3] LOCAL LOOKUP ON EACH NODE")
    print("-" * 72)
    per_node_results: Dict[str, int] = {}
    try:
        for nid, node in nodes.items():
            quantity = node.lookup_quantity(item_id, db[nid])
            per_node_results[nid] = quantity
            print(f"  Inventory {nid}: quantity of item {item_id} = {quantity}")
    except KeyError as exc:
        print(f"\nERROR: {exc}")
        print("Query aborted - item not present in the distributed ledger.")
        return

    # All nodes should return the same value because records were stored
    # consistently through Task 2's consensus. Sanity check this.
    distinct_results = set(per_node_results.values())
    if len(distinct_results) != 1:
        print("\nERROR: nodes disagree on the result - inventory inconsistency.")
        return
    message = per_node_results["A"]
    print(f"\nAll nodes agree: m = {message}")

    # Phase 1 of Harn signing - each node commits to its random nonce
    print("\n[STEP 4] HARN MULTI-SIGNATURE - PHASE 1: COMMITMENTS")
    print("-" * 72)
    print("Each inventory computes t_k = r_k ^ e mod n and broadcasts t_k.")
    t_values: Dict[str, int] = {}
    for nid, node in nodes.items():
        t_k = node.compute_commitment()
        t_values[nid] = t_k
        print(f"  Inventory {nid}: r_{nid} = {node.random_nonce}, t_{nid} = {t_k}")

    # Each node aggregates t independently - consensus check on t
    print("\n[STEP 5] HARN MULTI-SIGNATURE - PHASE 2: AGGREGATE COMMITMENT t")
    print("-" * 72)
    print("Every node independently computes t = t_A * t_B * t_C * t_D mod n.")
    per_node_t: Dict[str, int] = {}
    for nid in nodes:
        # Every node sees the same broadcast values, so they all multiply
        # the same set of t_k's. We pass an explicit list so the
        # computation is identical at every node.
        per_node_t[nid] = HarnInventoryNode.aggregate_commitments(
            list(t_values.values()), pkg.n
        )
        print(f"  Inventory {nid} computed t = {per_node_t[nid]}")

    t_agree, t_canonical = consensus_check_on_aggregates(
        {nid: (t_val, 0) for nid, t_val in per_node_t.items()}
    )
    if not t_agree:
        print("CONSENSUS FAILURE on aggregated t - aborting.")
        return
    t_aggregate = t_canonical[0]
    print(f"Consensus check on t: PASS  ->  t = {t_aggregate}")

    # Phase 2 of Harn signing - each node produces a partial signature s_k
    print("\n[STEP 6] HARN MULTI-SIGNATURE - PHASE 3: PARTIAL SIGNATURES")
    print("-" * 72)
    h_tm = hash_to_int(t_aggregate, message)
    print(f"H(t, m) = SHA256(t || m) interpreted as integer:")
    print(f"  H(t, m) = {h_tm}")

    s_values: Dict[str, int] = {}
    for nid, node in nodes.items():
        s_k = node.compute_partial_signature(t_aggregate, message)
        s_values[nid] = s_k
        print(f"  Inventory {nid}: s_{nid} = g_{nid} * r_{nid}^H(t,m) mod n = {s_k}")

    # Each node aggregates s; consensus check on (t, s)
    print("\n[STEP 7] AGGREGATE SIGNATURE s AND CONSENSUS CHECK")
    print("-" * 72)
    print("Every node independently computes s = s_A * s_B * s_C * s_D mod n.")
    per_node_aggregates: Dict[str, Tuple[int, int]] = {}
    for nid in nodes:
        s_agg = HarnInventoryNode.aggregate_partial_signatures(
            list(s_values.values()), pkg.n
        )
        per_node_aggregates[nid] = (t_aggregate, s_agg)
        print(f"  Inventory {nid}: aggregated (t, s) = ({t_aggregate}, {s_agg})")

    all_agree, canonical_ts = consensus_check_on_aggregates(per_node_aggregates)
    if not all_agree:
        print("CONSENSUS FAILURE: nodes disagree on aggregated (t, s) - aborting.")
        return
    t_final, s_final = canonical_ts
    print(f"\nConsensus check on (t, s): PASS")
    print(f"  Multi-signature = (t, s) = ({t_final}, {s_final})")

    # PKG verifies the multi-signature
    print("\n[STEP 8] MULTI-SIGNATURE VERIFICATION BY PKG")
    print("-" * 72)
    identities_in_order = [nodes[nid].identity for nid in sorted(nodes)]
    is_valid, lhs, rhs = verify_harn_multisignature(
        t_final, s_final, message, identities_in_order, pkg.e, pkg.n
    )
    print(f"  Left side  : s^e mod n                 = {lhs}")
    print(f"  Right side : (Pi i_k) * t^H(t,m) mod n = {rhs}")
    print(f"  Multi-signature valid? {is_valid}")
    if not is_valid:
        print("Multi-signature INVALID - response will not be delivered.")
        return

    # PKG encrypts the approved result with the Officer's public key
    print("\n[STEP 9] PKG ENCRYPTS THE RESULT FOR THE OFFICER")
    print("-" * 72)
    print(f"Plaintext result m         = {message}")
    print(f"Officer's public key (e,n) = ({officer.e}, {officer.n})")
    ciphertext = rsa_encrypt(message, officer.e, officer.n)
    print(f"Ciphertext c = m^e mod n   = {ciphertext}")

    # PKG sends { c, t, s, public parameters } to the officer
    print("\n[STEP 10] DELIVERY TO OFFICER")
    print("-" * 72)
    payload = {
        "ciphertext": ciphertext,
        "t": t_final,
        "s": s_final,
        "queried_item_id": item_id,
        "signer_identities": identities_in_order,
        "pkg_public_key": {"e": pkg.e, "n": pkg.n},
    }
    print("Payload sent to Officer:")
    for k, v in payload.items():
        print(f"  {k} = {v}")

    # Officer decrypts the response and verifies the multi-signature
    print("\n[STEP 11] OFFICER DECRYPTS AND VERIFIES")
    print("-" * 72)
    decrypted = officer.decrypt(ciphertext)
    print(f"Officer decrypts: m' = c^d_officer mod n_officer = {decrypted}")

    officer_check_valid, lhs2, rhs2 = verify_harn_multisignature(
        payload["t"],
        payload["s"],
        decrypted,
        payload["signer_identities"],
        payload["pkg_public_key"]["e"],
        payload["pkg_public_key"]["n"],
    )
    print(f"Officer re-verifies multi-signature using PKG's public key:")
    print(f"  Left side  = {lhs2}")
    print(f"  Right side = {rhs2}")
    print(f"  Signature valid at Officer? {officer_check_valid}")

    print("\n" + "=" * 72)
    if officer_check_valid and decrypted == message:
        print(f"SUCCESS: Officer recovered quantity of item {item_id} = {decrypted}")
        print("Response was jointly approved by all 4 inventory nodes, encrypted")
        print("for the Officer, and authenticated end-to-end.")
    else:
        print("FAILURE: response could not be authenticated.")
    print("=" * 72)


# COMMAND-LINE INTERFACE
def cli_menu() -> None:
    while True:
        print("\n" + "#" * 72)
        print("# Secure DLT Inventory - Task 3: Query Verification & Secure Delivery")
        print("#" * 72)
        print("Available items (Figure 1):")
        for rec in INITIAL_RECORDS:
            print(f"  - item_id={rec['item_id']}  qty={rec['quantity']}  "
                  f"price={rec['price']}  location={rec['location']}")
        print("\nOptions:")
        print("  [1] Query an item")
        print("  [2] Run demo query (item 002)")
        print("  [q] Quit")
        choice = input("Choose: ").strip().lower()

        if choice == "1":
            item_id = input("Enter item_id to query (e.g. 001/002/003/004): ").strip()
            run_secure_query(item_id)
        elif choice == "2":
            run_secure_query("002")
        elif choice == "q":
            print("Goodbye.")
            break
        else:
            print("Unrecognised option.")


if __name__ == "__main__":
    cli_menu()