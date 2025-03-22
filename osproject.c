#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32  // 32 bytes = 256-bit AES key
#define AES_BLOCK_SIZE 16

// Function to generate a random IV
void generateIV(unsigned char *iv) {
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
        exit(EXIT_FAILURE);
    }
}

// Encrypt function
int encryptFile(const char *inputFile, const char *outputFile, const unsigned char *key) {
    unsigned char iv[AES_BLOCK_SIZE];
    generateIV(iv); // Generate a random IV

    FILE *in = fopen(inputFile, "rb");
    FILE *out = fopen(outputFile, "wb");
    if (!in || !out) {
        perror("File opening failed");
        return 0;
    }

    // Write IV at the beginning of the file
    fwrite(iv, 1, AES_BLOCK_SIZE, out);
    printf("Encryption IV: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x ", iv[i]);
    printf("\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1024], cipherBuffer[1024 + AES_BLOCK_SIZE];
    int bytesRead, cipherLen;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, cipherBuffer, &cipherLen, buffer, bytesRead);
        fwrite(cipherBuffer, 1, cipherLen, out);
    }

    EVP_EncryptFinal_ex(ctx, cipherBuffer, &cipherLen);
    fwrite(cipherBuffer, 1, cipherLen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    printf("Encryption completed!\n");
    return 1;
}

// Decrypt function
int decryptFile(const char *inputFile, const char *outputFile, const unsigned char *key) {
    FILE *in = fopen(inputFile, "rb");
    FILE *out = fopen(outputFile, "wb");
    if (!in || !out) {
        perror("File opening failed");
        return 0;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
        printf("Error reading IV!\n");
        fclose(in);
        fclose(out);
        return 0;
    }
    printf("IV Read Successfully\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1024 + AES_BLOCK_SIZE], plainBuffer[1024];
    int bytesRead, plainLen;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        printf("Read %d bytes from encrypted file\n", bytesRead);
        EVP_DecryptUpdate(ctx, plainBuffer, &plainLen, buffer, bytesRead);
        printf("Decrypted %d bytes\n", plainLen);
        fwrite(plainBuffer, 1, plainLen, out);
    }

    if (EVP_DecryptFinal_ex(ctx, plainBuffer, &plainLen) == 0) {
        printf("Decryption Finalization Failed! Possible incorrect key or corrupted data.\n");
    } else {
        printf("Final Decrypted %d bytes\n", plainLen);
        fwrite(plainBuffer, 1, plainLen, out);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    printf("Decryption Completed\n");
    return 1;
}



int main() {
    const unsigned char key[AES_KEY_SIZE] = {
        't', 'h', 'i', 's', '_', 'i', 's', '_', 'a', '_', '3', '2', '_', 'b', 'y', 't',
        'e', '_', 'k', 'e', 'y', '_', 'f', 'o', 'r', '_', 'A', 'E', 'S', '!', '\0', '\0'
    };
    
    char inputFile[256], outputFile[256], choice;

    printf("Enter 'e' for encryption or 'd' for decryption: ");
    scanf(" %c", &choice);

    if (choice == 'e') {
        printf("Enter input file name: ");
        scanf("%s", inputFile);
        printf("Enter output encrypted file name: ");
        scanf("%s", outputFile);

        if (encryptFile(inputFile, outputFile, key))
            printf("File encrypted successfully!\n");
        else
            printf("Encryption failed!\n");

    } else if (choice == 'd') {
        printf("Enter encrypted file name: ");
        scanf("%s", inputFile);
        printf("Enter output decrypted file name: ");
        scanf("%s", outputFile);

        if (decryptFile(inputFile, outputFile, key))
            printf("File decrypted successfully!\n");
        else
            printf("Decryption failed!\n");

    } else {
        printf("Invalid choice!\n");
    }

    return 0;
}
