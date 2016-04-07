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
#include <Wincrypt.h>
#include <stdio.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#include "common.h"
#include "base64.h"
#include "aes256.h"

static bool generateKey(HCRYPTKEY *key, HCRYPTPROV provider, ALG_ID algid, const unsigned char *password, unsigned long pLen)
{
	if (!provider || password == NULL)
		return false;

	HCRYPTHASH hash;

	if (!CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash))
	{
		printf("Error: %d\n", GetLastError());
		return false;
	}

	if (!hash)
		return false;

	if (!CryptHashData(hash, password, pLen, 0))
	{
		CryptDestroyHash(hash);
		return false;
	}

	if (!CryptDeriveKey(provider, algid, hash, CRYPT_EXPORTABLE, key))
	{
		CryptDestroyHash(hash);
		return false;
	}

	CryptDestroyHash(hash);
	return true;
}

bool CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, unsigned char **iv, const unsigned char *password, unsigned long pLen)
{
	unsigned long mode = CRYPT_MODE_CBC;
	unsigned long blockSize, blockSizeLen = sizeof(unsigned long);

	if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_AES, 0))
	{
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			if (!CryptAcquireContextW(provider, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				printf("Error: %d\n", GetLastError());
				return false;
			}
		}
		else
		{
			printf("Error: %d\n", GetLastError());
			return false;
		}
	}

	if (!generateKey(key, *provider, CALG_AES_256, password, pLen))
	{
		printf("Error: %d\n", GetLastError());
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptSetKeyParam(*key, KP_MODE, (BYTE *)&mode, 0))
	{
		printf("Error: %d\n", GetLastError());
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptGetKeyParam(*key, KP_BLOCKLEN, (BYTE *)&blockSize, &blockSizeLen, 0))
	{
		printf("Error: %d\n", GetLastError());
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	blockSize /= 8;

	*iv = (unsigned char *)malloc(blockSize * sizeof(unsigned char));
	if (*iv == NULL)
	{
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}
	SecureZeroMemory(*iv, blockSize * sizeof(unsigned char));

	if (!CryptGenRandom(*provider, blockSize, *iv))
	{
		printf("Error: %d\n", GetLastError());
		SAFE_FREE(*iv);
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	if (!CryptSetKeyParam(*key, KP_IV, *iv, 0))
	{
		printf("Error: %d\n", GetLastError());
		SAFE_FREE(*iv);
		if (*key) CryptDestroyKey(*key);
		if (*provider) CryptReleaseContext(*provider, 0);
		return false;
	}

	return true;
}

bool Encrypt(HCRYPTKEY key, char **cipherText, unsigned long *cLen, unsigned char *plainText, unsigned long pLen)
{
	unsigned long len = 0;
	unsigned char *encrypted = 0;
	unsigned long enLen = 0;

	len = pLen + 1;

	if (!CryptEncrypt(key, 0, TRUE, 0, NULL, &len, 0))
	{
		if (key) CryptDestroyKey(key);
		return false;
	}

	enLen = len;

	encrypted = (unsigned char *)malloc(len * sizeof(unsigned char));
	if (encrypted == NULL)
	{
		if (key) CryptDestroyKey(key);
		return false;
	}
	SecureZeroMemory(encrypted, len * sizeof(unsigned char));

	memcpy_s(encrypted, len, plainText, pLen + 1);

	len = pLen + 1;
	if (!CryptEncrypt(key, 0, TRUE, 0, encrypted, &len, enLen))
	{
		SAFE_FREE(encrypted);
		if (key) CryptDestroyKey(key);
		return false;
	}

	if (!Base64EncodeA(cipherText, cLen, encrypted, enLen))
	{
		SAFE_FREE(encrypted);
		if (key) CryptDestroyKey(key);
		return false;
	}

	SAFE_FREE(encrypted);

	return true;
}

bool Decrypt(HCRYPTKEY key, unsigned char **plainText, char *cipherText, unsigned long cLen)
{
	unsigned long len = 0;
	unsigned long decodedLen = 0;
	char *decoded = 0;

	if (!Base64DecodeA(&decoded, &decodedLen, cipherText, cLen))
	{
		if (key) CryptDestroyKey(key);
		return false;
	}

	*plainText = (unsigned char *)malloc(decodedLen * sizeof(unsigned char));
	if (*plainText == NULL)
	{
		if (key) CryptDestroyKey(key);
		return false;
	}
	SecureZeroMemory(*plainText, decodedLen * sizeof(unsigned char));

	memcpy_s(*plainText, decodedLen, decoded, decodedLen);

	SAFE_FREE(decoded);

	len = decodedLen;
	if (!CryptDecrypt(key, 0, TRUE, 0, *plainText, &len))
	{
		SAFE_FREE(*plainText);
		if (key) CryptDestroyKey(key);
		return false;
	}

	return true;
}

void CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider)
{
	if (key) if (!CryptDestroyKey(key)) printf("Error: %d\n", GetLastError());
	if (provider) if (!CryptReleaseContext(provider, 0)) printf("Error: %d\n", GetLastError());
}
