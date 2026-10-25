#include "block/Padding.h"

int missingFor(int len, int blockSize)
{
	return blockSize - (len % blockSize);
}

void pad(std::vector<uint8_t>& buf, int missing, Padding type)
{
	if (missing <= 0)
		return;

	switch (type)
	{
		case Padding::None:
			return;
		case Padding::Zeros:
			for (int i = 0; i < missing; ++i)
				buf.push_back((uint8_t) 0);
			return;
		case Padding::PKCS7:
			for (int i = 0; i < missing; ++i)
				buf.push_back((uint8_t) missing);
			return;
		case Padding::ANSIX923:
			for (int i = 0; i < missing - 1; ++i)
				buf.push_back((uint8_t) 0);
			buf.push_back((uint8_t) missing);
			return;
		case Padding::ISO78164:
			buf.push_back((uint8_t) 0x80);
			for (int i = 0; i < missing - 1; ++i)
				buf.push_back((uint8_t) 0);
			return;
	}
}

bool unpad(std::vector<uint8_t>& buf, Padding type, int blockSize)
{
	int l = (int) buf.size();
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
			uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return false;
			for (int i = 0; i < n; ++i)
				if (buf[l - 1 - i] != n)
					return false;
			buf.resize(l - n);
			return true;
		}
		case Padding::ANSIX923:
		{
			uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return false;
			for (int i = 1; i < n; ++i)
				if (buf[l - 1 - i] != 0)
					return false;
			buf.resize(l - n);
			return true;
		}
		case Padding::ISO78164:
		{
			int i = l - 1;
			while (i >= l - blockSize && buf[i] == 0)
				--i;
			if (i < l - blockSize || buf[i] != 0x80)
				return false;
			buf.resize(i);
			return true;
		}
	}
	return false;
}
