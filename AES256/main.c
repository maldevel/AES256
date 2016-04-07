/*
AES256 - AES 256 CBC encryption and Base64 encoding with CryptoAPI and C
Copyright (C) 2016  @maldevel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Windows.h>
#include <stdio.h>
#include "common.h"
#include "aes256.h"

int main(void)
{
	HCRYPTPROV hCryptProv = 0;
	HCRYPTKEY key = 0;
	unsigned char *iv = 0;
	unsigned long cLen = 0;
	char *cipherText = 0;
	char *plainText = "PLAIN_TEXT_PLAIN_TEXT\0";
	char *password = "!TESTING_PASS_TESTING_PASS_TESTING_PASS!\0";
	unsigned char *decrypted = 0;

	if (!CryptoInit(&key, &hCryptProv, &iv, password, strlen(password)))
	{
		printf("Crypto initializing failed\n");
		return EXIT_FAILURE;
	}

	if (!Encrypt(key, &cipherText, &cLen, (unsigned char *)plainText, strlen(plainText)))
	{
		printf("Encryption failed\n");
		if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
		return EXIT_FAILURE;
	}

	printf("Encrypted string: %s\n", cipherText);

	if (!Decrypt(key, &decrypted, cipherText, cLen))
	{
		printf("Decryption failed\n");
		SAFE_FREE(cipherText);
		if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
		return EXIT_FAILURE;
	}

	SAFE_FREE(cipherText);

	printf("Decrypted string: %s\n", decrypted);

	SAFE_FREE(decrypted);

	CryptoUninit(key, hCryptProv);

	SAFE_FREE(iv);

	return EXIT_SUCCESS;
}
