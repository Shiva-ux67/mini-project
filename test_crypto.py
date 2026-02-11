from crypto_utils import feistel_encrypt, feistel_decrypt

key = "shiva_secret_key"
message = "Help! Fraud detected in Seller A's shop."

# Encrypt
encrypted = feistel_encrypt(message, key)
print(f"Encrypted: {encrypted}")

# Decrypt
decrypted = feistel_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")