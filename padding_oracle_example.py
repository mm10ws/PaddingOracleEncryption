import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Standard AES CBC decrypt function (128 bit key)
def decrypt(data):
    # In the real world, we wouldn't know this key, but would still be able to create a valid
    # cipher text that would be able to be decrypted by this key
    key = b"Thisisakey!!!!!!"

    # First 16 bytes is the IV
    iv = data[0:16]

    # Everything else is the ciphertext
    ctext = data[16:]

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    ptext = decryptor.update(ctext) + decryptor.finalize()
    return ptext


# This is the padding oracle, it returns true if there is no padding error, false otherwise.
# In the real world this could be anything, like a website that gives a slightly different
# error if the padding is wrong.
def padded_oracle_check_local(data):
    # First decrypt the data
    ptext = decrypt(data)

    # Now try to remove the padding (using PKCS7 padding)
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(ptext)

    try:
        data += unpadder.finalize()
    except Exception:
        # Throw an error if it has incorrect padding aka padding oracle
        return False

    # If we made it to this point there was no error, valid padding
    return True


# Implements the main logic of the padding oracle encryption attack
def attack():
    # What we want to encrypt using the padding oracle (can be anything we want like valid json
    # to spoof an admin account). Make sure it has valid padding.
    plaintxt_to_find = bytearray(b'{"role":"admin","user":"a"}\x05\x05\x05\x05\x05')

    # Start off with a random block to use as our last block of ciphertext (this can also be whatever
    # you want but I chose random)
    prev_block = bytearray(os.urandom(16))

    # The block we are trying to calculate using the padding oracle (starts off as all zeros, but will
    # be calculated byte by byte)
    to_calc_block = bytearray(b"\x00" * 16)

    # Variable to hold the final calculated ciphertext that corresponds to the plaintxt_to_find
    final_ciphertext = prev_block

    # Find number of plaintext blocks
    num_blocks_to_calc = len(plaintxt_to_find) // 16

    # For each block that we need to calculate...
    for b in range(0, num_blocks_to_calc):
        # Get the 16 byte block of the plaintext (working our way from the end to the front)
        pblock_index = num_blocks_to_calc - b - 1
        plaintext_block = plaintxt_to_find[16 * pblock_index : 16 * pblock_index + 16]

        # For each byte in the block to calculate...
        for i in range(0, 16):
            # Again working our way from the last byte to the first
            byte_index = 15 - i
            found_byte = False

            # For each byte value...
            for j in range(0, 256):
                print(f"Trying {j}")

                # Try the two blocks together to see if there is a padding error when decrypted
                to_calc_block[byte_index] = j
                test_ctext = to_calc_block + prev_block
                success = padded_oracle_check_local(test_ctext)
                if success:
                    # Padding oracle reported that there was no padding error so our guess was correct
                    print(f"found: {j}")
                    found_byte = True
                    if byte_index > 0:
                        # Update all the bytes to the end so the padding is correct to calculate the next byte
                        for x in range(byte_index, 16):
                            to_calc_block[x] = to_calc_block[x] ^ (i + 1) ^ (i + 2)
                    print(to_calc_block)
                    break

            if not found_byte:
                print(f"something went wrong: {byte_index}")
                return False

        # We calculated a full block, do an xor with the plaintext block so it decrypts to what we want
        for i in range(0, 16):
            to_calc_block[i] = to_calc_block[i] ^ 16 ^ plaintext_block[i]

        # Setup for next block
        prev_block = to_calc_block
        to_calc_block = bytearray(b"\x00" * 16)
        final_ciphertext = prev_block + final_ciphertext

    # At this point we have a full iv + ciphertext that will decrypt to the plaintext we want
    print(f"Final ctext: {final_ciphertext}")
    print(f"Decrypts to: {decrypt(final_ciphertext)}")
    return True


if __name__ == "__main__":
    while True:
        success = attack()
        if success:
            break
