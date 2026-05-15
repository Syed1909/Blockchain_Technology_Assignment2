# Task 3 - Harn multi-signature query verification and secure delivery

import hashlib
import json
import os


# PKG keys (Part 2 of List of Keys)
PKG_P = 1004162036461488639338597000466705179253226703
PKG_Q = 950133741151267522116252385927940618264103623
PKG_E = 973028207197278907211

# Procurement Officer's RSA keys
OFFICER_P = 1080954735722463992988394149602856332100628417
OFFICER_Q = 1158106283320086444890911863299879973542293243
OFFICER_E = 106506253943651610547613

# Each inventory's public identity
IDENTITIES = {"A": 126, "B": 127, "C": 128, "D": 129}

# Random nonce for each node
RANDOMS = {"A": 621, "B": 721, "C": 821, "D": 921}

# Figure 1 records (used if main.py hasn't run yet)
INITIAL_RECORDS = [
    {"item_id": "001", "quantity": 32, "price": 12, "location": "D"},
    {"item_id": "002", "quantity": 20, "price": 14, "location": "C"},
    {"item_id": "003", "quantity": 22, "price": 16, "location": "B"},
    {"item_id": "004", "quantity": 12, "price": 18, "location": "A"},
]

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def hash_to_int(*parts):
    joined = "|".join(str(p) for p in parts)
    return int.from_bytes(hashlib.sha256(joined.encode()).digest(), "big")


# PKG class
class PKG:
    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.d = pow(e, -1, self.phi)

    def issue_secret_key(self, identity):
        # g_k = id ^ d mod n
        return pow(identity, self.d, self.n)


# Procurement Officer class
class Officer:
    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.d = pow(e, -1, self.phi)

    def decrypt(self, c):
        # m = c ^ d mod n
        return pow(c, self.d, self.n)


# An inventory node in the Harn scheme
class InventoryNode:
    def __init__(self, node_id, identity, r, g_k, pkg_e, pkg_n):
        self.node_id = node_id
        self.identity = identity
        self.r = r          # random nonce
        self.g_k = g_k      # secret key from PKG
        self.pkg_e = pkg_e
        self.pkg_n = pkg_n

    def lookup(self, item_id, db):
        for record in db:
            if record["item_id"] == item_id:
                return record["quantity"]
        raise KeyError("item not found in inventory " + self.node_id)

    def commit(self):
        # t_k = r_k ^ e mod n
        return pow(self.r, self.pkg_e, self.pkg_n)

    def partial_sign(self, t, m):
        # s_k = g_k * r_k ^ H(t,m) mod n
        h = hash_to_int(t, m)
        return (self.g_k * pow(self.r, h, self.pkg_n)) % self.pkg_n


# Multiply a list of values mod n
def product_mod(values, n):
    result = 1
    for v in values:
        result = (result * v) % n
    return result


# RSA encrypt: c = m^e mod n
def rsa_encrypt(m, e, n):
    if m >= n:
        raise ValueError("m must be smaller than n")
    return pow(m, e, n)


# Harn verification: check s^e == (product of identities) * t^H(t,m) mod n
def verify_multisig(t, s, m, identities, pkg_e, pkg_n):
    lhs = pow(s, pkg_e, pkg_n)
    id_product = product_mod(identities, pkg_n)
    h = hash_to_int(t, m)
    rhs = (id_product * pow(t, h, pkg_n)) % pkg_n
    return lhs == rhs, lhs, rhs


# Load each node's records from disk, seed from INITIAL_RECORDS if missing
def load_databases():
    os.makedirs(DATA_FOLDER, exist_ok=True)
    db = {}
    for node_id in IDENTITIES:
        path = os.path.join(DATA_FOLDER, "inventory_" + node_id + ".json")
        records = []
        if os.path.exists(path):
            with open(path) as f:
                loaded = json.load(f)
            for r in loaded:
                if "item_id" in r and "quantity" in r:
                    records.append(r)
        if not records:
            records = [dict(r) for r in INITIAL_RECORDS]
            with open(path, "w") as f:
                json.dump(records, f, indent=2)
        db[node_id] = records
    return db


# Main workflow
def run_query(item_id):
    print("=" * 50)
    print("TASK 3 - SECURE RECORD RETRIEVAL")
    print("=" * 50)

    # Step 1: setup
    print("\n[Step 1] Setup")
    print("-" * 50)
    pkg = PKG(PKG_P, PKG_Q, PKG_E)
    officer = Officer(OFFICER_P, OFFICER_Q, OFFICER_E)
    db = load_databases()

    print("PKG params:")
    print("  p   =", pkg.p)
    print("  q   =", pkg.q)
    print("  n   =", pkg.n)
    print("  phi =", pkg.phi)
    print("  e   =", pkg.e)
    print("  d   =", pkg.d)

    print("\nOfficer params:")
    print("  n =", officer.n)
    print("  e =", officer.e)
    print("  d =", officer.d)

    print("\nIssuing secret keys g_k = id ^ d mod n:")
    nodes = {}
    for node_id, identity in IDENTITIES.items():
        g_k = pkg.issue_secret_key(identity)
        nodes[node_id] = InventoryNode(node_id, identity, RANDOMS[node_id],
                                        g_k, pkg.e, pkg.n)
        print("  Node " + node_id + ": id=" + str(identity) +
              ", r=" + str(RANDOMS[node_id]) + ", g=" + str(g_k))

    # Step 2: officer sends query
    print("\n[Step 2] Query submission")
    print("-" * 50)
    print("Officer asks PKG: what is the quantity of item " + item_id + "?")
    print("PKG forwards the query to all 4 inventories")

    # Step 3: each node looks up the item
    print("\n[Step 3] Local lookup")
    print("-" * 50)
    results = {}
    try:
        for nid, node in nodes.items():
            qty = node.lookup(item_id, db[nid])
            results[nid] = qty
            print("  Node " + nid + ": quantity =", qty)
    except KeyError as e:
        print("ERROR:", e)
        return

    if len(set(results.values())) != 1:
        print("ERROR: nodes disagree on the result")
        return
    m = results["A"]
    print("\nAll nodes agree, m =", m)

    # Step 4: phase 1 - commitments
    print("\n[Step 4] Harn phase 1: commitments")
    print("-" * 50)
    print("Each node computes t_k = r_k ^ e mod n")
    t_values = {}
    for nid, node in nodes.items():
        t_k = node.commit()
        t_values[nid] = t_k
        print("  Node " + nid + ": t =", t_k)

    # Step 5: aggregate t (each node does this independently)
    print("\n[Step 5] Aggregate t (consensus check)")
    print("-" * 50)
    per_node_t = {}
    for nid in nodes:
        per_node_t[nid] = product_mod(t_values.values(), pkg.n)
        print("  Node " + nid + " computed t =", per_node_t[nid])

    if len(set(per_node_t.values())) != 1:
        print("CONSENSUS FAIL on t")
        return
    t = per_node_t["A"]
    print("Consensus check on t: PASS")

    # Step 6: phase 2 - partial signatures
    print("\n[Step 6] Harn phase 2: partial signatures")
    print("-" * 50)
    h = hash_to_int(t, m)
    print("H(t,m) =", h)
    s_values = {}
    for nid, node in nodes.items():
        s_k = node.partial_sign(t, m)
        s_values[nid] = s_k
        print("  Node " + nid + ": s = g * r^H(t,m) mod n =", s_k)

    # Step 7: aggregate s (consensus check again)
    print("\n[Step 7] Aggregate s (consensus check)")
    print("-" * 50)
    per_node_s = {}
    for nid in nodes:
        per_node_s[nid] = product_mod(s_values.values(), pkg.n)
        print("  Node " + nid + ": (t,s) =", (t, per_node_s[nid]))

    if len(set(per_node_s.values())) != 1:
        print("CONSENSUS FAIL on s")
        return
    s = per_node_s["A"]
    print("Consensus check on (t,s): PASS")
    print("Multi-signature (t,s) =", (t, s))

    # Step 8: PKG verifies the multi-signature
    print("\n[Step 8] PKG verifies multi-signature")
    print("-" * 50)
    ids = [nodes[nid].identity for nid in sorted(nodes)]
    ok, lhs, rhs = verify_multisig(t, s, m, ids, pkg.e, pkg.n)
    print("LHS s^e mod n =", lhs)
    print("RHS (prod id) * t^H(t,m) mod n =", rhs)
    print("Valid?", ok)
    if not ok:
        print("Verification failed, not delivering")
        return

    # Step 9: encrypt result with officer's public key
    print("\n[Step 9] Encrypt result for officer")
    print("-" * 50)
    print("m =", m)
    print("Officer public key (e,n) =", (officer.e, officer.n))
    c = rsa_encrypt(m, officer.e, officer.n)
    print("Ciphertext c = m^e mod n =", c)

    # Step 10: send package to officer
    print("\n[Step 10] Send to officer")
    print("-" * 50)
    payload = {
        "ciphertext": c,
        "t": t,
        "s": s,
        "item_id": item_id,
        "identities": ids,
        "pkg_public": (pkg.e, pkg.n),
    }
    for k, v in payload.items():
        print(" ", k, "=", v)

    # Step 11: officer decrypts and re-verifies
    print("\n[Step 11] Officer decrypts and verifies")
    print("-" * 50)
    decrypted = officer.decrypt(c)
    print("Officer decrypts m =", decrypted)

    ok2, lhs2, rhs2 = verify_multisig(payload["t"], payload["s"], decrypted,
                                       payload["identities"],
                                       payload["pkg_public"][0],
                                       payload["pkg_public"][1])
    print("LHS =", lhs2)
    print("RHS =", rhs2)
    print("Valid?", ok2)

    print("\n" + "=" * 50)
    if ok2 and decrypted == m:
        print("SUCCESS: item " + item_id + " quantity =", decrypted)
    else:
        print("FAIL")
    print("=" * 50)


# Menu
def menu():
    while True:
        print("\n" + "#" * 50)
        print("Task 3 - Query verification and secure delivery")
        print("#" * 50)
        print("Items available:")
        for r in INITIAL_RECORDS:
            print("  - " + r["item_id"] + ": qty=" + str(r["quantity"]) +
                  " price=" + str(r["price"]) + " loc=" + r["location"])
        print("\n[1] Query an item")
        print("[2] Demo query (item 002)")
        print("[q] Quit")
        choice = input("Choose: ").strip().lower()

        if choice == "1":
            item_id = input("Enter item id (eg 001, 002, 003, 004): ").strip()
            run_query(item_id)
        elif choice == "2":
            run_query("002")
        elif choice == "q":
            break
        else:
            print("Unknown option")


if __name__ == "__main__":
    menu()