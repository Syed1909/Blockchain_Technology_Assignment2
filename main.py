import json
import hashlib
import os
from dataclasses import dataclass, field
from typing import Dict, List



# PART 1 HARD CODED KEYS
RAW_KEYS = {
    "A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801,
    },
    "B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787,
    },
    "C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057,
    },
    "D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979,
    },
}

INITIAL_RECORDS = [
    {"item_id": "001", "quantity": 32, "price": 12, "location": "D"},
    {"item_id": "002", "quantity": 20, "price": 14, "location": "C"},
    {"item_id": "003", "quantity": 22, "price": 16, "location": "B"},
]


# DATA MODELS
@dataclass
class InventoryNode:
    node_id: str
    p: int
    q: int
    e: int
    n: int = field(init=False)
    phi: int = field(init=False)
    d: int = field(init=False)
    storage_file: str = field(init=False)

    def __post_init__(self) -> None:
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)
        self.storage_file = os.path.join("data", f"inventory_{self.node_id}.json")

    def public_key(self) -> tuple[int, int]:
        return self.e, self.n

    def private_key(self) -> tuple[int, int]:
        return self.d, self.n


# UTILITY FUNCTIONS
def ensure_data_folder() -> None:
    os.makedirs("data", exist_ok=True)


def initialise_storage(nodes: Dict[str, InventoryNode]) -> None:
    """Create each node's storage file pre-loaded with the Figure-1 records
    (001, 002, 003) if the file doesn't already exist.
    """
    ensure_data_folder()
    for node in nodes.values():
        if not os.path.exists(node.storage_file):
            with open(node.storage_file, "w", encoding="utf-8") as f:
                json.dump(list(INITIAL_RECORDS), f, indent=2)


def stable_record_string(record: Dict) -> str:
    """
    Convert record into a consistent string using the four Figure-1 fields
    in a fixed order. The same record content must always hash to the
    same value, so the field order is locked here.
    """
    return (
        f"{record['item_id']}|"
        f"{record['quantity']}|"
        f"{record['price']}|"
        f"{record['location']}"
    )


def hash_record(record_string: str) -> int:
    digest = hashlib.sha256(record_string.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


def sign_record(record_string: str, signer: InventoryNode) -> Dict:
    message_int = hash_record(record_string)
    message_mod_n = message_int % signer.n
    signature = pow(message_mod_n, signer.d, signer.n)

    return {
        "message_hash_int": message_int,
        "message_mod_n": message_mod_n,
        "signature": signature,
    }


def verify_signature(record_string: str, signature: int, sender_public_e: int, sender_public_n: int) -> bool:
    message_int = hash_record(record_string)
    message_mod_n = message_int % sender_public_n
    recovered = pow(signature, sender_public_e, sender_public_n)
    return recovered == message_mod_n


def append_record_to_node(node: InventoryNode, record_package: Dict) -> None:
    with open(node.storage_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    records.append(record_package)

    with open(node.storage_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


# TASK 2: SIMPLIFIED CONSENSUS
def run_majority_consensus(
    sender_id: str,
    record_string: str,
    signature: int,
    nodes: Dict[str, InventoryNode]
) -> Dict:
    sender = nodes[sender_id]
    votes: List[Dict] = []
    accept_count = 1  # sender is treated as accepting its own generated record
    total_nodes = len(nodes)

    print("\n=== VERIFICATION BY OTHER INVENTORY NODES ===")
    for node_id, node in nodes.items():
        if node_id == sender_id:
            continue

        is_valid = verify_signature(record_string, signature, sender.e, sender.n)
        vote = "ACCEPT" if is_valid else "REJECT"
        if is_valid:
            accept_count += 1

        votes.append({
            "verifier": node_id,
            "valid_signature": is_valid,
            "vote": vote,
        })

        print(f"[Node {node_id}] Verifying Node {sender_id}'s record...")
        print(f"Result: {'VALID' if is_valid else 'INVALID'}")
        print(f"Vote: {vote}\n")

    # Majority rule
    majority_needed = (total_nodes // 2) + 1
    accepted = accept_count >= majority_needed

    print("=== CONSENSUS RESULT ===")
    print(f"Accept votes: {accept_count}/{total_nodes}")
    print(f"Majority needed: {majority_needed}")
    print(f"Final decision: {'ACCEPTED' if accepted else 'REJECTED'}\n")

    return {
        "accepted": accepted,
        "votes": votes,
        "accept_count": accept_count,
        "majority_needed": majority_needed,
    }


# MAIN DEMO WORKFLOW
def build_nodes() -> Dict[str, InventoryNode]:
    return {
        node_id: InventoryNode(node_id=node_id, p=vals["p"], q=vals["q"], e=vals["e"])
        for node_id, vals in RAW_KEYS.items()
    }


def print_rsa_parameters(node: InventoryNode) -> None:
    print(f"--- RSA PARAMETERS FOR INVENTORY {node.node_id} ---")
    print(f"p   = {node.p}")
    print(f"q   = {node.q}")
    print(f"e   = {node.e}")
    print(f"n   = {node.n}")
    print(f"phi = {node.phi}")
    print(f"d   = {node.d}")
    print()


def main() -> None:
    nodes = build_nodes()
    initialise_storage(nodes)

    # Choose the originating node for this demo
    sender_id = "A"
    sender = nodes[sender_id]

    # Show derived RSA values for the sending node
    print_rsa_parameters(sender)

    # STEP 1: CREATE A NEW INVENTORY RECORD - matches Figure 1 (004 from A)
    record = {
        "item_id": "004",
        "quantity": 12,
        "price": 18,
        "location": "A",
    }
    record_string = stable_record_string(record)

    print("=== STEP 1: RECORD CREATION ===")
    print(f"Originating node: Inventory {sender_id}")
    print(f"Record: {record}")
    print(f"Stable record string: {record_string}\n")

    # STEP 2: SIGN THE RECORD
    signed = sign_record(record_string, sender)

    print("=== STEP 2: DIGITAL SIGNATURE GENERATION ===")
    print(f"SHA-256 hash as integer: {signed['message_hash_int']}")
    print(f"Hash mod n: {signed['message_mod_n']}")
    print(f"Signature: {signed['signature']}\n")

    # STEP 3 + 4: VERIFY + CONSENSUS
    consensus_result = run_majority_consensus(
        sender_id=sender_id,
        record_string=record_string,
        signature=signed["signature"],
        nodes=nodes,
    )

    # STEP 5: STORE RECORD IF ACCEPTED
    # We store the record itself (not a wrapper around it) so Task 3 can
    # look it up by item_id directly.
    if consensus_result["accepted"]:
        print("=== STEP 5: STORING ACCEPTED RECORD IN ALL NODES ===")
        for node in nodes.values():
            append_record_to_node(node, record)
            print(f"Stored in Inventory {node.node_id}: {node.storage_file}")
        print("\nRecord successfully stored in all local inventory databases.")
    else:
        print("Record was rejected. No storage performed.")


if __name__ == "__main__":
    main()