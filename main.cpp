#include <Windows.h>
#include "xts.h"

int main()
{
	byte key[2*CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	memset(key+CryptoPP::AES::DEFAULT_KEYLENGTH, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);


	LARGE_INTEGER freq;
	QueryPerformanceFrequency(&freq);

	CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption xtsE;
	CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption xtsD;

	xtsE.SetKeyWithIV(key, 2*CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
	xtsD.SetKeyWithIV(key, 2 * CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

	size_t bufferSize = 0x20;
	byte *src, *dst;

	src = new byte[bufferSize]();
	dst = new byte[bufferSize];

	DWORD start, stop;

	start = GetTickCount();
	xtsE.ProcessData(src, src, bufferSize);
	xtsD.ProcessData(src, src, bufferSize);
	stop = GetTickCount();

	printf("%d\n", stop - start);

	delete[] src;
	delete[] dst;

	return 0;
}
