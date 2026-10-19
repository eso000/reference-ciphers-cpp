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

void unpad(std::vector<uint8_t>& buf, Padding type, int blockSize)
{
	int l = (int) buf.size();
	if (l == 0 || l % blockSize != 0)
		return;

	switch (type)
	{
		case Padding::None:
		case Padding::Zeros:
			return;
		case Padding::PKCS7:
		{
			uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return;
			for (int i = 0; i < n; ++i)
				if (buf[l - 1 - i] != n)
					return;
			buf.resize(l - n);
			return;
		}
		case Padding::ANSIX923:
		{
			uint8_t n = buf[l - 1];
			if (n < 1 || n > blockSize)
				return;
			for (int i = 1; i < n; ++i)
				if (buf[l - 1 - i] != 0)
					return;
			buf.resize(l - n);
			return;
		}
		case Padding::ISO78164:
		{
			int i = l - 1;
			while (i >= l - blockSize && buf[i] == 0)
				--i;
			if (i >= l - blockSize && buf[i] == 0x80)
				buf.resize(i);
			return;
		}
	}
}
