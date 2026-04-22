import hashlib

# Inventory A keys
p = 1210613765735147311106936311866593978079938707
q = 1247842850282035753615951347964437248190231863
e = 815459040813953176289801

n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print("n =", n)
print("phi =", phi)
print("d =", d)

record = "004|12|18|A"
print("\nRecord =", record)

record_hash = hashlib.sha256(record.encode()).digest()
message_int = int.from_bytes(record_hash, "big")
message_mod = message_int % n

print("Message integer =", message_int)
print("Message mod n =", message_mod)

signature = pow(message_mod, d, n)
print("Signature =", signature)

verified_value = pow(signature, e, n)
print("Verified value =", verified_value)

if verified_value == message_mod:
    print("Signature is VALID")
else:
    print("Signature is INVALID")
