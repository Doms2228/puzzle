import hashlib
import base58
from coincurve import PrivateKey
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import random
import sys
import os

# Define the target public key and Bitcoin address
TARGET_PUBLIC_KEY = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
TARGET_ADDRESS = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"

# Checkpoint directory to save progress for each process
CHECKPOINT_DIR = "checkpoints_random"

# Create checkpoint directory if it doesn't exist
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

# Function to derive a compressed Bitcoin address from a private key
def private_key_to_compressed_address(private_key_hex):
    try:
        # Convert the private key from hex string to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Generate the public key using coincurve
        private_key = PrivateKey(private_key_bytes)
        public_key = private_key.public_key.format(compressed=True).hex()  # Compressed public key
        
        # Hash the public key to generate the Bitcoin address
        sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        
        # Add network byte (0x00 for mainnet Bitcoin)
        network_byte = b"\x00" + hashed_public_key
        
        # Compute checksum (first 4 bytes of double SHA-256 hash)
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        
        # Encode in Base58 to get the Bitcoin address
        binary_address = network_byte + checksum
        bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
        
        return bitcoin_address, public_key
    except Exception as e:
        print(f"Error generating compressed address: {e}")
        return None, None

# Function to perform randomized brute-force search in a single process
def random_brute_force_process(start, end, total_tests_per_process, process_id):
    # Define the checkpoint file for this process
    checkpoint_file = os.path.join(CHECKPOINT_DIR, f"checkpoint_{process_id}.txt")
    
    # Load previously tested private keys from the checkpoint file
    used_keys = set()
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            for line in f:
                used_keys.add(line.strip())
    
    for i in range(total_tests_per_process):
        while True:
            # Generate a random private key within the range
            private_key_int = random.randint(start, end)
            private_key_hex = f"{private_key_int:064x}"  # Convert to 64-character hex string
            
            # Check if the private key has already been used
            if private_key_hex not in used_keys:
                used_keys.add(private_key_hex)  # Mark the private key as used
                
                # Update the checkpoint file
                with open(checkpoint_file, "a") as f:
                    f.write(f"{private_key_hex}\n")
                
                break  # Exit the loop if the key is unique
        
        # Derive the Bitcoin address and public key
        bitcoin_address, public_key = private_key_to_compressed_address(private_key_hex)
        
        # Update progress dynamically (every 100 iterations)
        if i % 100 == 0:  # Reduced frequency to avoid slowing down
            progress = (i + 1) / total_tests_per_process * 100
            sys.stdout.write(f"\rProcess {process_id}: Progress: {progress:.2f}% | Testing private key: {private_key_hex}")
            sys.stdout.flush()
        
        # Check if the derived public key matches the target
        if public_key == TARGET_PUBLIC_KEY:
            print(f"\nPrivate key found: {private_key_hex}")
            print(f"Bitcoin address: {bitcoin_address}")
            return private_key_hex
    
    print(f"\nProcess {process_id} completed. Private key not found.")
    return None

# Main function to execute the brute-force search with multiple processes
if __name__ == "__main__":
    # Define the range of private keys to search
    START_KEY = 0x4000000000000000000000000000000000
    END_KEY = 0x7fffffffffffffffffffffffffffffffff
    
    # Total number of random tests across all processes
    TOTAL_TESTS = 1000000000  # 1 billion random tests (adjust based on hardware)
    
    # Number of processes
    NUM_PROCESSES = multiprocessing.cpu_count()  # Use all available CPU cores
    
    # Divide the total tests among the processes
    TESTS_PER_PROCESS = TOTAL_TESTS // NUM_PROCESSES
    
    # Perform the random brute-force search using multiple processes
    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        futures = []
        for process_id in range(NUM_PROCESSES):
            future = executor.submit(random_brute_force_process, START_KEY, END_KEY, TESTS_PER_PROCESS, process_id)
            futures.append(future)
        
        # Wait for all processes to complete and check results
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)  # Exit early if a private key is found
    
    print("Search completed. Private key not found.")