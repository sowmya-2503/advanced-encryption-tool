*COMPANY*:CODTECH IT SOLUTIONS

*NAME*:TAMMU SOWMYA

*INTERN ID*:CT06DL381

*DOMAIN*:CYBER SECURITY

*DURATION*:4 WEEKS

*MENTOR*:NEELA SANTOSH
 
  Core Features

Strong encryption with AES-256 (256-bit keys).

Password-based encryption using PBKDF2 with SHA-256.

Random salt and IV for each file to enhance security.

Simple GUI to choose files and perform operations without the command line.

    Main Components

derive_key(password, salt)

Uses PBKDF2HMAC with SHA-256 to generate a secure AES key from a user password and random salt. Makes brute-force attacks much harder.

encrypt_file(file_path, password)

Reads and pads the plaintext.

Generates a random salt and IV.

Derives a key using the password and salt.

Encrypts the data using AES-256 in CBC mode.

Prepends salt + IV to the ciphertext.

Saves the result as a .enc file.

Shows a success message with output path.

decrypt_file(file_path, password)

Extracts the salt and IV from the encrypted file.

Derives the same key from the password and salt.

Decrypts the ciphertext and removes padding.

Saves the output as a .dec file.

![Image](https://github.com/user-attachments/assets/287a1fc7-9be7-48f4-a365-d673a09fd0f8)
