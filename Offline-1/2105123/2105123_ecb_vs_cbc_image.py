import importlib
import os
from PIL import Image
import matplotlib.pyplot as plt

aes = importlib.import_module("2105123_aes")

def encrypt_image_ecb_vs_cbc(image_path, key_str, key_size, output_prefix="bonus_1/bonus1_output"):
    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    original_image = Image.open(image_path).convert("RGB")
    width, height = original_image.size
    pixel_bytes = list(original_image.tobytes())
    print(f"Image size: {width}x{height}, total pixel bytes: {len(pixel_bytes)}")

    Nk, Nr, total_words = aes.initialize_parameter(key_size)
    key_bytes = aes.normalize_key(key_str, Nk * 4)
    w = aes.key_expansion(key_bytes, Nk, Nr, total_words)
    ecb_ciphertext = aes.aes_ecb_encrypt(pixel_bytes, w, Nr)
    cbc_ciphertext_with_iv = aes.aes_cbc_encrypt(pixel_bytes, w, Nr)
    cbc_ciphertext = cbc_ciphertext_with_iv[16:]  
    ecb_pixels = ecb_ciphertext[:len(pixel_bytes)]
    cbc_pixels = cbc_ciphertext[:len(pixel_bytes)]
    ecb_image = Image.frombytes("RGB", (width, height), bytes(ecb_pixels))
    cbc_image = Image.frombytes("RGB", (width, height), bytes(cbc_pixels))

    original_image.save(f"{output_prefix}_original.png")
    ecb_image.save(f"{output_prefix}_ecb_encrypted.png")
    cbc_image.save(f"{output_prefix}_cbc_encrypted.png")

    plt.figure(figsize=(12, 4))

    plt.subplot(1, 3, 1)
    plt.title("Original")
    plt.imshow(original_image)
    plt.axis("off")

    plt.subplot(1, 3, 2)
    plt.title(f"Encrypted (ECB) - {key_size}-bit")
    plt.imshow(ecb_image)
    plt.axis("off")

    plt.subplot(1, 3, 3)
    plt.title(f"Encrypted (CBC) - {key_size}-bit")
    plt.imshow(cbc_image)
    plt.axis("off")

    plt.tight_layout()
    plt.savefig(f"{output_prefix}_side_by_side.png")
    plt.show()    

    ecb_decrypted = aes.aes_ecb_decrypt(ecb_ciphertext, w, Nr)
    cbc_decrypted = aes.aes_cbc_decrypt(cbc_ciphertext_with_iv, w, Nr)
    if ecb_decrypted == pixel_bytes:
        ebc_dec_image = Image.frombytes("RGB", (width, height), bytes(ecb_decrypted))
        print("ECB decryption PASSED - original pixels has been recovered")
        plt.figure(figsize=(12, 4))

        plt.subplot(1, 3, 1)
        plt.title("Original")
        plt.imshow(original_image)
        plt.axis("off")

        plt.subplot(1, 3, 2)
        plt.title(f"Encrypted (ECB) - {key_size}-bit")
        plt.imshow(ecb_image)
        plt.axis("off")

        plt.subplot(1, 3, 3)
        plt.title(f"Decrypted (ECB) - {key_size}-bit")
        plt.imshow(ebc_dec_image)
        plt.axis("off")

        plt.tight_layout()
        plt.savefig(f"{output_prefix}_side_by_side.png")
        plt.show()  
    else:
        print("ECB decryption become MISMATCH")

    if cbc_decrypted == pixel_bytes:
        cbc_dec_image = Image.frombytes("RGB", (width, height), bytes(cbc_decrypted))
        print("CBC decryption PASSED - original pixels has been recovered")
        plt.figure(figsize=(12, 4))

        plt.subplot(1, 3, 1)
        plt.title("Original")
        plt.imshow(original_image)
        plt.axis("off")

        plt.subplot(1, 3, 2)
        plt.title(f"Encrypted (CBC) - {key_size}-bit")
        plt.imshow(cbc_image)
        plt.axis("off")

        plt.subplot(1, 3, 3)
        plt.title(f"Decrypted (CBC) - {key_size}-bit")
        plt.imshow(cbc_dec_image)
        plt.axis("off")

        plt.tight_layout()
        plt.savefig(f"{output_prefix}_side_by_side.png")
        plt.show()          
    else:
        print("CBC decryption become MISMATCH")

    print("\nSaved images:")
    print(f"  {output_prefix}_original.png")
    print(f"  {output_prefix}_ecb_encrypted.png")
    print(f"  {output_prefix}_cbc_encrypted.png")
    print(f"  {output_prefix}_side_by_side.png")


if __name__ == "__main__":
    KEY = "BUET CSE21 Batch"
    key_input = input("Input Key Size (128/192/256) [Default: 128]: ").strip()
    KEY_SIZE = int(key_input) if key_input else 128
    FILE_PATH = input("Input the image file path : ").strip()
    if not os.path.exists(FILE_PATH):
        print(f"Error: The file '{FILE_PATH}' does not exist!")
        exit(1)    
    encrypt_image_ecb_vs_cbc(FILE_PATH, KEY,KEY_SIZE)
