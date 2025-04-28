import hashlib
import base58
from coincurve import PrivateKey
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import random
import sys

# Define the target Bitcoin addresses as a set
TARGET_ADDRESSES = {"1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"}

# Checkpoint file to save progress
CHECKPOINT_FILE = "checkpoint71.txt"

# Function to derive a compressed Bitcoin address from a private key
def private_key_to_compressed_address(private_key_hex):
    try:
        # Convert the private key from hex string to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Generate the public key using coincurve
        private_key = PrivateKey(private_key_bytes)
        public_key = private_key.public_key.format(compressed=True)  # Compressed public key
        
        # Hash the public key to generate the Bitcoin address
        sha256_hash = hashlib.sha256(public_key).digest()
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
        
        return bitcoin_address
    except Exception as e:
        print(f"Error generating compressed address: {e}")
        return None

# Function to perform randomized brute-force search in a single process
def random_brute_force_process(start, end, total_tests_per_process, process_id, used_keys):
    for i in range(total_tests_per_process):
        while True:
            # Generate a random private key within the range
            private_key_int = random.randint(start, end)
            private_key_hex = f"{private_key_int:064x}"  # Convert to 64-character hex string
            
            # Check if the private key has already been used
            if private_key_hex not in used_keys:
                used_keys.add(private_key_hex)  # Mark the private key as used
                break  # Exit the loop if the key is unique
        
        # Derive the Bitcoin address from the private key
        bitcoin_address = private_key_to_compressed_address(private_key_hex)
        
        # Update progress dynamically (every 100 iterations)
        if i % 100 == 0:  # Reduced frequency to avoid slowing down
            progress = (i + 1) / total_tests_per_process * 100
            sys.stdout.write(f"\rProcess {process_id}: Progress: {progress:.2f}% | Testing private key: {private_key_hex}")
            sys.stdout.flush()
        
        # Check if the derived Bitcoin address matches any of the target addresses
        if bitcoin_address in TARGET_ADDRESSES:
            print(f"\nPrivate key found: {private_key_hex}")
            print(f"Bitcoin address: {bitcoin_address}")
            return private_key_hex
    
    print(f"\nProcess {process_id} completed. Private key not found.")
    return None

# Main function to execute the brute-force search with multiple processes
if __name__ == "__main__":
    # Define the range of private keys to search (for Puzzle #68)
    START_KEY = 0x400000000000000000  # Start of the range for Puzzle #69
    END_KEY = 0x7fffffffffffffffff    # End of the range for Puzzle #69
    
    # Total number of random tests across all processes
    TOTAL_TESTS = 1000000000  # Reduced to 1 billion random tests
    
    # Number of processes
    NUM_PROCESSES = multiprocessing.cpu_count()  # Use all available CPU cores
    
    # Divide the total tests among the processes
    TESTS_PER_PROCESS = TOTAL_TESTS // NUM_PROCESSES
    
    # Perform the random brute-force search using multiple processes
    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        futures = []
        for process_id in range(NUM_PROCESSES):
            # Create a unique set for each process to track used private keys
            used_keys = set()
            future = executor.submit(random_brute_force_process, START_KEY, END_KEY, TESTS_PER_PROCESS, process_id, used_keys)
            futures.append(future)
        
        # Wait for all processes to complete and check results
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)  # Exit early if a private key is found
    
    print("Search completed. Private key not found.")