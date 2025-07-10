import os
import shutil

def findXorKey(encrypted_data, expected_header="UnityFS"):
    expected_bytes = expected_header.encode("utf-8")
    header_length = len(expected_bytes)

    if len(encrypted_data) < header_length:
        print("File too short!")
        return 0

    possible_key = 0

    for xor_key in range(256):
        match = True
        # Check ALL header bytes for this key
        for i in range(header_length):
            if (encrypted_data[i] ^ xor_key) != expected_bytes[i]:
                match = False
                break
        if match:
            possible_key = xor_key

    return possible_key

def decrypt_data(encrypted_data):
    decrypted = bytearray(encrypted_data)
    
    key = findXorKey(encrypted_data)

    for i in range(len(decrypted)):
        decrypted[i] ^= key

    return bytes(decrypted)

def process_folder(input_folder, output_folder):
    for root, dirs, files in os.walk(input_folder):
        relative_path = os.path.relpath(root, input_folder)
        dest_root = os.path.join(output_folder, relative_path)
        
        for file in files:
            src_path = os.path.join(root, file)
            dest_path = os.path.join(dest_root, file)
            
            if os.path.exists(dest_path):
                continue
                
            # Check for .unity3d files
            if file.endswith('.unity3d'):
                with open(src_path, 'rb') as f:
                    header = f.read(7)
                    f.seek(0)
                    data = f.read()
                
                # Check if file is encrypted by checking header
                if header != b'UnityFS':
                    data = decrypt_data(data)
                    dest_path = dest_path[:-len('.unity3d')] + '_decrypted.unity3d'

                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, 'wb') as f:
                    f.write(data)

                unpack_folder = dest_path + '_unpacked'                
            else:
                os.makedirs(dest_root, exist_ok=True)
                shutil.copy2(src_path, dest_path)

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_folder = os.path.join(script_dir, 'input')
    output_folder = os.path.join(script_dir, 'output')
    
    process_folder(input_folder, output_folder)
    print("Processing complete! Check the output folder.")