import hashlib

def round_function(right_half_bytes, key):
    """
    Standardizes the scramble using HMAC-like SHA256 logic.
    Works on bytes to avoid encoding errors.
    """
    hash_input = right_half_bytes + key.encode()
    return hashlib.sha256(hash_input).digest()

def feistel_encrypt(plaintext, key, rounds=4):
    """
    Encrypts text into a secure Hex string.
    """
    # 1. Padding: Feistel requires an even number of bytes
    data = plaintext.encode('utf-8')
    if len(data) % 2 != 0:
        data += b' '
        
    # 2. Split into Left and Right halves
    mid = len(data) // 2
    left = data[:mid]
    right = data[mid:]

    # 3. Permutation Rounds
    for i in range(rounds):
        # f_output is the 'scramble' based on the current Right half and Secret Key
        f_output = round_function(right, key)
        
        # XOR the Left half with the scramble to create the New Right
        new_right = bytes([left[j] ^ f_output[j % len(f_output)] for j in range(len(left))])
        
        # New Left is just the old Right (Swapping)
        left = right
        right = new_right

    # 4. Final concatenation and conversion to HEX for database storage
    return (left + right).hex()

def feistel_decrypt(hex_ciphertext, key, rounds=4):
    """
    Reverses the Feistel rounds to recover the original text.
    """
    try:
        # 1. Convert HEX back to bytes
        data = bytes.fromhex(hex_ciphertext)
        mid = len(data) // 2
        left = data[:mid]
        right = data[mid:]

        # 2. Reverse the rounds
        # In Feistel, decryption is identical to encryption but the halves are swapped
        for i in range(rounds):
            temp_left = left
            f_output = round_function(left, key)
            
            # XOR the Right half with the scramble to get the original Left
            new_left = bytes([right[j] ^ f_output[j % len(f_output)] for j in range(len(right))])
            
            right = temp_left
            left = new_left

        # 3. Re-combine and remove padding
        return (left + right).decode('utf-8').strip()
    except Exception as e:
        # If the key is wrong or data is corrupted, this will trigger
        raise ValueError("Decryption failed. Likely incorrect key.")