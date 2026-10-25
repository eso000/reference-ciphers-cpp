#include "block/Padding.h"

namespace block {

size_t missingFor(size_t len, size_t blockSize)
{
	return blockSize - (len % blockSize);
}

void pad(std::vector<uint8_t>& buf, size_t missing, Padding type)
{
	if (missing == 0)
		return;

	switch (type)
	{
		case Padding::None:
			return;
		case Padding::Zeros:
			buf.insert(buf.end(), missing, uint8_t{0});
			return;
		case Padding::PKCS7:
			buf.insert(buf.end(), missing, static_cast<uint8_t>(missing));
			return;
		case Padding::ANSIX923:
			buf.insert(buf.end(), missing - 1, uint8_t{0});
			buf.push_back(static_cast<uint8_t>(missing));
			return;
		case Padding::ISO78164:
			buf.push_back(uint8_t{0x80});
			buf.insert(buf.end(), missing - 1, uint8_t{0});
			return;
	}
}

bool unpad(std::vector<uint8_t>& buf, Padding type, size_t blockSize)
{
	const size_t l = buf.size();
	if (l == 0)
	{
		/* An empty buffer carries no padding block, so it is only valid when
		   the scheme does not require one. */
		return type == Padding::None || type == Padding::Zeros;
	}
	if (l % blockSize != 0)
		return false;

	switch (type)
	{
		case Padding::None:
		case Padding::Zeros:
			return true;
		case Padding::PKCS7:
		{
			const uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return false;
			for (size_t i = 0; i < n; ++i)
				if (buf[l - 1 - i] != n)
					return false;
			buf.resize(l - n);
			return true;
		}
		case Padding::ANSIX923:
		{
			const uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return false;
			for (size_t i = 1; i < n; ++i)
				if (buf[l - 1 - i] != 0)
					return false;
			buf.resize(l - n);
			return true;
		}
		case Padding::ISO78164:
		{
			/* Skip zero bytes back from the end, but never past the last
			   block; the byte they stop at must be the 0x80 marker. */
			const size_t floor = l - blockSize;
			size_t end = l;
			while (end > floor && buf[end - 1] == 0)
				--end;
			if (end == floor || buf[end - 1] != 0x80)
				return false;
			buf.resize(end - 1);
			return true;
		}
	}
	return false;
}

} // namespace block
