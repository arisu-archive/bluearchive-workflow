import argparse
import xxhash
import random
import json
from base64 import b64encode, b64decode

CONFIG_KEYS = [
    "SkipTutorial",
    "ServerInfoDataUrl",
    "Language",
    "DefaultConnectionGroup",
]


def init_mt19937(seed: int) -> random.Random:
    """Initialize a Mersenne Twister RNG with a given seed."""
    rng = random.Random()
    state_size = 624
    mt_state = [0] * state_size
    mt_state[0] = seed & 0xFFFFFFFF

    for i in range(1, state_size):
        mt_state[i] = (
            1812433253 * (mt_state[i - 1] ^ (mt_state[i - 1] >> 30)) + i
        ) & 0xFFFFFFFF

    mt_state.append(state_size)
    rng.setstate((3, tuple(mt_state), None))
    return rng


def generate_encryption_key(id_str: str, size: int = 8) -> bytes:
    """Generate a key using a hash of the identifier and MT19937 RNG."""
    seed = xxhash.xxh32_intdigest(id_str.encode("utf-8"))
    rng = init_mt19937(seed)

    key_bytes = bytearray()
    for _ in range(0, size, 4):
        # Get 32 random bits, shift right by 1, convert to 4 bytes
        random_int = rng.getrandbits(32) >> 1
        chunk = random_int.to_bytes(4, "little", signed=False)
        key_bytes.extend(chunk)

    return bytes(key_bytes)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Perform XOR operation between data and key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_config(data: bytes) -> dict:
    """Decrypt the configuration using a generated key."""
    key = generate_encryption_key("GameMainConfig")
    decrypted = xor_bytes(data, key)
    return json.loads(decrypted)


def process_config_entries(encrypted: dict, keys: list) -> dict:
    """Process and decrypt each configuration key."""
    result = {}

    for config_key in keys:
        # Generate a key specific to this config entry
        encryption_key = generate_encryption_key(config_key)

        # Create a lookup key by encoding, XORing, and base64 encoding
        config_bytes = config_key.encode("utf-16le")
        encoded_lookup = xor_bytes(config_bytes, encryption_key)
        lookup_key = b64encode(encoded_lookup).decode()
        # Look up the encrypted value and decrypt it
        if lookup_key in encrypted:
            encrypted_value = b64decode(encrypted[lookup_key])
            decrypted_bytes = xor_bytes(encrypted_value, encryption_key)
            result[config_key] = decrypted_bytes.decode("utf-16le")
        else:
            raise KeyError(f"Key '{config_key}' not found")

    return result


def main(in_path: str, out_path: str):
    """Main function to read, decrypt, and write the configuration."""
    with open(in_path, "rb") as f:
        data = f.read()

    encrypted = decrypt_config(data)
    result = process_config_entries(encrypted, CONFIG_KEYS)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a configuration file.")
    parser.add_argument(
        "-i", "--input", type=str, required=True, help="Input encrypted file path"
    )
    parser.add_argument(
        "-o", "--output", type=str, required=True, help="Output decrypted file path"
    )

    args = parser.parse_args()
    main(args.input, args.output)
