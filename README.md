import cv2
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import numpy as np
import time

# RSA parameters for share 1
p1 = 8839
q1 = 9743
e1 = 13

# RSA parameters for share 2
p2 = 9973
q2 = 9929
e2 = 17

# Function to generate RSA keys
def generate_rsa_keys(p, q, e):
    n = p * q
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

# Generate keys for share 1
public_key_1, private_key_1 = generate_rsa_keys(p1, q1, e1)

# Generate keys for share 2
public_key_2, private_key_2 = generate_rsa_keys(p2, q2, e2)

# Function to perform RSA encryption on blocks of data
def rsa_encrypt_blocks(data, public_key):
    encrypted_blocks = []
    max_data_length = public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    for i in range(0, len(data), max_data_length):
        block = data[i:i + max_data_length]
        encrypted_block = public_key.encrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_blocks.append(encrypted_block)
    return encrypted_blocks

# Function to perform RSA decryption on blocks of data
def rsa_decrypt_blocks(blocks, private_key):
    decrypted_data = b""
    for block in blocks:
        decrypted_block = private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_data += decrypted_block
    return decrypted_data

# Function to add noise to share
def add_noise(share):
    noise = np.random.randint(-10, 10, size=share.shape)
    noisy_share = share + noise
    return noisy_share

# Read the image and resize
image_path = r'C:\Users\roren\OneDrive\Desktop\GP 2 python\RSA.jpg'
original_image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
resized_image = cv2.resize(original_image, (original_image.shape[1] // 2, original_image.shape[0] // 2))

# Split each pixel into 8 sub pixels
height, width = resized_image.shape
sub_pixels = np.zeros((height, width, 8), dtype=np.uint8)
for i in range(height):
    for j in range(width):
        pixel = resized_image[i, j]
        binary_pixel = format(pixel, '08b')
        for k in range(8):
            sub_pixels[i, j, k] = int(binary_pixel[k])

# Generate pairs of shares
shares = []
for i in range(2):
    share = np.zeros((height, width, 8), dtype=np.uint8)
    for j in range(height):
        for k in range(width):
            for l in range(8):
                share[j, k, l] = sub_pixels[j, k, l]
    shares.append(share)

# Encrypt the first share using RSA
start_encrypt_time_1 = time.time()
encrypted_share_1 = rsa_encrypt_blocks(shares[0].flatten().tobytes(), public_key_1)
end_encrypt_time_1 = time.time()
encryption_time_1 = end_encrypt_time_1 - start_encrypt_time_1

# Encrypt the second share using RSA
start_encrypt_time_2 = time.time()
encrypted_share_2 = rsa_encrypt_blocks(shares[1].flatten().tobytes(), public_key_2)
end_encrypt_time_2 = time.time()
encryption_time_2 = end_encrypt_time_2 - start_encrypt_time_2

# Decrypt the first share
start_decrypt_time_1 = time.time()
decrypted_share_1 = rsa_decrypt_blocks(encrypted_share_1, private_key_1)
decrypted_share_1 = np.frombuffer(decrypted_share_1, dtype=np.uint8)
decrypted_share_1 = decrypted_share_1.reshape(height, width, 8)
end_decrypt_time_1 = time.time()
decryption_time_1 = end_decrypt_time_1 - start_decrypt_time_1

# Decrypt the second share
start_decrypt_time_2 = time.time()
decrypted_share_2 = rsa_decrypt_blocks(encrypted_share_2, private_key_2)
decrypted_share_2 = np.frombuffer(decrypted_share_2, dtype=np.uint8)
decrypted_share_2 = decrypted_share_2.reshape(height, width, 8)
end_decrypt_time_2 = time.time()
decryption_time_2 = end_decrypt_time_2 - start_decrypt_time_2

# Combine shares
combined_share = np.zeros((height, width, 8), dtype=np.uint8)
for j in range(height):
    for k in range(width):
        for l in range(8):
            combined_share[j, k, l] = (decrypted_share_1[j, k, l] + decrypted_share_2[j, k, l]) // 2

# Convert combined share back to grayscale image
decrypted_image_final = np.zeros((height, width), dtype=np.uint8)
for i in range(height):
    for j in range(width):
        binary_pixel = ''.join(map(str, combined_share[i, j]))
        decrypted_image_final[i, j] = int(binary_pixel, 2)

# Calculate MSE, PSNR, NPCR, VACI for all images
mse = np.mean((resized_image.astype(np.float32) - decrypted_image_final.astype(np.float32)) ** 2)
psnr = cv2.PSNR(resized_image, decrypted_image_final)
npcr = np.count_nonzero(resized_image != decrypted_image_final) / (height * width)
vac = np.abs(np.mean(resized_image) - np.mean(decrypted_image_final))

# Key Size (bits) - For the key used for the first share (or you could choose to display the other key if preferred)
key_size_bits = public_key_1.key_size

# Security Margin (Example Calculation)
security_margin = key_size_bits - 128  # Adjust 128 based on the typical key size

# System Response (Example: Time taken for encryption and decryption)
encryption_response = (encryption_time_1 + encryption_time_2) / 2
decryption_response = (decryption_time_1 + decryption_time_2) / 2

# Print results
print(f"MSE: {mse}")
print(f"PSNR: {psnr}")
print(f"NPCR: {npcr}")
print(f"VACI: {vac}")
print(f"Key Size: {key_size_bits} bits")
print(f"Security Margin: {security_margin} bits")
print(f"Average Encryption Time: {encryption_response} seconds")
print(f"Average Decryption Time: {decryption_response} seconds")

# Display images using OpenCV
cv2.namedWindow('Original Image', cv2.WINDOW_NORMAL)
cv2.resizeWindow('Original Image', 400, 400)  # Set window size to 400x400
cv2.imshow('Original Image', resized_image)

cv2.namedWindow('Encrypted Image', cv2.WINDOW_NORMAL)
cv2.resizeWindow('Encrypted Image', 400, 400)  # Set window size to 400x400
encrypted_image_data_1 = b''.join(encrypted_share_1)
encrypted_image_1 = np.frombuffer(encrypted_image_data_1, dtype=np.uint8)
# Ensure the encrypted image has the right size
encrypted_image_1 = encrypted_image_1[:height * width * 8].reshape(height, width, 8).mean(axis=2).astype(np.uint8)
cv2.imshow('Encrypted Image', encrypted_image_1)

cv2.namedWindow('Decrypted Image', cv2.WINDOW_NORMAL)
cv2.resizeWindow('Decrypted Image', 400, 400)  # Set window size to 400x400
cv2.imshow('Decrypted Image', decrypted_image_final)

# Display shares
cv2.namedWindow('Share 1', cv2.WINDOW_NORMAL)
cv2.resizeWindow('Share 1', 400, 400)  # Set window size to 400x400
cv2.imshow('Share 1', shares[0].mean(axis=2).astype(np.uint8))  # Display share 1

cv2.namedWindow('Share 2', cv2.WINDOW_NORMAL)
cv2.resizeWindow('Share 2', 400, 400)  # Set window size to 400x400
cv2.imshow('Share 2', shares[1].mean(axis=2).astype(np.uint8))  # Display share 2

cv2.waitKey(0)
cv2.destroyAllWindows()
