#ifndef CRYPTOPP_XTS_H
#define CRYPTOPP_XTS_H

#include "modes.h"
#include "aes.h"

NAMESPACE_BEGIN(CryptoPP)

class XTS_ModeBase {
public:
	void UncheckedSetKey(const byte *key, unsigned int length);
	void Resynchronize(const byte *iv, int length = -1);
	void SetCiphers(BlockCipher &cipher, BlockCipher &cipher_iv) {
		m_cipher = &cipher;
		m_cipher_iv = &cipher_iv;
		ResizeBuffers();
	}
protected:
	XTS_ModeBase() : m_cipher(NULL), m_cipher_iv(NULL) {}
	inline unsigned int BlockSize() const { assert(m_register.size() > 0); return (unsigned int)m_register.size(); }
	void ResizeBuffers();
	void IncrementCounter();

	BlockCipher *m_cipher, *m_cipher_iv;
	AlignedSecByteBlock m_register;
	SecByteBlock m_buffer;
};

class XTS_Encryption : public XTS_ModeBase {
public:
	void ProcessData(byte *outString, const byte *inString, size_t length);
	void ProcessLastBlock(byte *outString, const byte *inString, size_t length);
};


class XTS_Decryption : public XTS_ModeBase {
public:
	void ProcessData(byte *outString, const byte *inString, size_t length);
	void ProcessLastBlock(byte *outString, const byte *inString, size_t length);
};

// template <class CIPHER, class IV_CIPHER, class BASE>

/*template <class CIPHER, 
struct XTS_Mode {

};*/

NAMESPACE_END

#endif
