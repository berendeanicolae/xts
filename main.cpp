#include "xts.h"

int main()
{
	byte key[2*CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	memset(key+CryptoPP::AES::DEFAULT_KEYLENGTH, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);


	CryptoPP::AES::Encryption aes_cipher(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::AES::Encryption aes_cipher_iv(key, CryptoPP::AES::DEFAULT_KEYLENGTH);


	CryptoPP::XTS_Encryption xts;

	xts.SetCiphers(aes_cipher, aes_cipher_iv);
	xts.UncheckedSetKey(key, 2*CryptoPP::AES::DEFAULT_KEYLENGTH);
	xts.Resynchronize(iv);

	byte block[0x20] = {};
	memset(block, 0x44, 0x20);

	xts.ProcessData(block, block, 0x20);

	return 0;
}
