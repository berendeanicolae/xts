#include "xts.h"

NAMESPACE_BEGIN(CryptoPP)

void CipherModeBase_::ResizeBuffers() {
	m_register.New(m_cipher->BlockSize());
}

void BlockOrientedCipherModeBase_::ResizeBuffers() {
	CipherModeBase_::ResizeBuffers();
	m_buffer.New(BlockSize());
}

void BlockOrientedCipherModeBase_::Resynchronize(const byte *iv, int length) {
	memcpy_s(m_register, m_register.size(), iv, ThrowIfInvalidIVLength(length));
	m_cipher_iv->ProcessBlock(m_register);
}

void BlockOrientedCipherModeBase_::UncheckedSetKey(const byte *key, unsigned int length, const NameValuePairs &params) {
	m_cipher->SetKey(key, length/2);
	m_cipher_iv->SetKey(key+length/2, length/2);
	ResizeBuffers();
	if (IsResynchronizable())
	{
		size_t ivLength;
		const byte *iv = GetIVAndThrowIfInvalid(params, ivLength);
		Resynchronize(iv, (int)ivLength);
	}
}


void XTS_ModeBase::IncrementCounter() {
	const __m128i r = _mm_setr_epi32(0x87, 0x0, 0x0, 0x0);
	const __m128i msb_mask = _mm_setr_epi32(0x0, 0x0, 0x0, 0x80000000);
	__m128i block = *(__m128i*)(void*)m_register;
	__m128i b1, b2;

	if (_mm_testz_si128(block, msb_mask)) {
		b1 = _mm_slli_epi64(block, 1);
		b2 = _mm_slli_si128(block, 8);
		b2 = _mm_srli_epi64(b2, 63);
		block = _mm_or_si128(b1, b2);
	}
	else {
		b1 = _mm_slli_epi64(block, 1);
		b2 = _mm_slli_si128(block, 8);
		b2 = _mm_srli_epi64(b2, 63);
		block = _mm_or_si128(b1, b2);
		block = _mm_xor_si128(block, r);
	}
	*(__m128i*)(void*)m_register = block;
}

void XTS_Encryption::ProcessData(byte *outString, const byte *inString, size_t length) {
	if (!length)
		return;
	assert(length%BlockSize() == 0);

	size_t blockSize = BlockSize();
	while (length >= blockSize) {
		xorbuf(m_buffer, inString, m_register, blockSize);
		m_cipher->ProcessBlock(m_buffer);
		xorbuf(m_buffer, m_register, blockSize);
		memcpy(outString, m_buffer, blockSize);

		inString += blockSize;
		outString += blockSize;
		length -= blockSize;
		IncrementCounter();
	}
}

void XTS_Encryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length) {
	assert(length >= BlockSize());

	if (length == BlockSize()) {
		xorbuf(outString, inString, m_register, BlockSize());
		m_cipher->ProcessBlock(outString);
		xorbuf(outString, m_register, BlockSize());

		IncrementCounter();
	}
	else {
		xorbuf(m_buffer, inString, m_register, BlockSize());
		m_cipher->ProcessBlock(m_buffer);
		xorbuf(m_buffer, m_register, BlockSize());

		IncrementCounter();

		length -= BlockSize();
		if (outString == inString) {
			memmove(outString, inString + BlockSize(), length);
			memcpy(outString + BlockSize(), m_buffer, length);
			memcpy(m_buffer, inString, length);
		}
		else {
			memcpy(outString + BlockSize(), m_buffer, length);
			memcpy(m_buffer, inString + BlockSize(), length);
		}

		xorbuf(m_buffer, m_register, BlockSize());
		m_cipher->ProcessBlock(m_buffer);
		xorbuf(m_buffer, m_register, BlockSize());

		memcpy(outString, m_buffer, BlockSize());

	}
}


void XTS_Decryption::ProcessLastBlock(byte *outString, const byte *inString, size_t length) {
	assert(length >= BlockSize());

	if (length == BlockSize()) {
		xorbuf(outString, inString, m_register, BlockSize());
		m_cipher->ProcessBlock(outString);
		xorbuf(outString, m_register, BlockSize());

		IncrementCounter();
	}
	else {
		xorbuf(m_buffer, inString, m_register, BlockSize());
		m_cipher->ProcessBlock(m_buffer);
		xorbuf(m_buffer, m_register, BlockSize());

		IncrementCounter();

		length -= BlockSize();
		if (outString == inString) {
			memmove(outString, inString + BlockSize(), length);
			memcpy(outString + BlockSize(), m_buffer, length);
			memcpy(m_buffer, inString, length);
		}
		else {
			memcpy(outString + BlockSize(), m_buffer, length);
			memcpy(m_buffer, inString + BlockSize(), length);
		}

		xorbuf(m_buffer, m_register, BlockSize());
		m_cipher->ProcessBlock(m_buffer);
		xorbuf(m_buffer, m_register, BlockSize());

		memcpy(outString, m_buffer, BlockSize());

	}
}

NAMESPACE_END
