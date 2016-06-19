#ifndef CRYPTOPP_XTS_H
#define CRYPTOPP_XTS_H

#include "modes.h"
#include "aes.h"

NAMESPACE_BEGIN(CryptoPP)

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE CipherModeBase_ : public SymmetricCipher
{
public:
	size_t MinKeyLength() const { return m_cipher->MinKeyLength() + m_cipher_iv->MinKeyLength(); }
	size_t MaxKeyLength() const { return m_cipher->MaxKeyLength() + m_cipher_iv->MaxKeyLength(); }
	size_t DefaultKeyLength() const { return m_cipher->DefaultKeyLength() + m_cipher_iv->DefaultKeyLength(); }
	size_t GetValidKeyLength(size_t n) const { return m_cipher->GetValidKeyLength(n); } //TODO:
	bool IsValidKeyLength(size_t n) const { return m_cipher->IsValidKeyLength(n); } //TODO:

	unsigned int OptimalDataAlignment() const { return m_cipher->OptimalDataAlignment(); } //TODO:

	unsigned int IVSize() const { return BlockSize(); }
	virtual IV_Requirement IVRequirement() const = 0;

	void SetCiphers(BlockCipher &cipher, BlockCipher &cipher_iv) //TODO:
	{
		this->ThrowIfResynchronizable();
		this->m_cipher = &cipher;
		this->m_cipher_iv = &cipher_iv;
		this->ResizeBuffers();
	}

	void SetCiphersWithIV(BlockCipher &cipher, BlockCipher &cipher_iv, const byte *iv, int feedbackSize = 0) //TODO:
	{
		this->ThrowIfInvalidIV(iv);
		this->m_cipher = &cipher;
		this->m_cipher_iv = &cipher_iv;
		this->ResizeBuffers();
		this->SetFeedbackSize(feedbackSize);
		if (this->IsResynchronizable())
			this->Resynchronize(iv);
	}

protected:
	CipherModeBase_() : m_cipher(NULL), m_cipher_iv(NULL) {}
	inline unsigned int BlockSize() const { assert(m_register.size() > 0); return (unsigned int)m_register.size(); }
	virtual void SetFeedbackSize(unsigned int feedbackSize) //TODO:
	{
		if (!(feedbackSize == 0 || feedbackSize == BlockSize()))
			throw InvalidArgument("CipherModeBase: feedback size cannot be specified for this cipher mode");
	}
	virtual void ResizeBuffers();

	BlockCipher *m_cipher, *m_cipher_iv;
	AlignedSecByteBlock m_register;
};

class CRYPTOPP_DLL CRYPTOPP_NO_VTABLE BlockOrientedCipherModeBase_ : public CipherModeBase_
{
public:
	void UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params); //TODO:
	unsigned int MandatoryBlockSize() const { return BlockSize(); }
	bool IsRandomAccess() const { return false; }
	bool IsSelfInverting() const { return false; }
	bool IsForwardTransformation() const { return m_cipher->IsForwardTransformation(); }
	void Resynchronize(const byte *iv, int length = -1) { memcpy_s(m_register, m_register.size(), iv, ThrowIfInvalidIVLength(length)); } //TODO:

protected:
	bool RequireAlignedInput() const { return true; }
	void ResizeBuffers();

	SecByteBlock m_buffer;
};


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
