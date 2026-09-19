CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2

CORE    = BlockCipher.cpp Padding.cpp
CIPHERS = AES Blowfish Twofish DES Serpent
TESTS   = $(CIPHERS:%=%Test) GenericModeTest

.PHONY: all test clean

all: $(TESTS)

%Test: %Test.cpp %.cpp $(CORE) $(wildcard *.h)
	$(CXX) $(CXXFLAGS) $< $*.cpp $(CORE) -o $@

GenericModeTest: GenericModeTest.cpp $(CIPHERS:%=%.cpp) $(CORE) $(wildcard *.h)
	$(CXX) $(CXXFLAGS) $< $(CIPHERS:%=%.cpp) $(CORE) -o $@

test: all
	@fail=0; \
	for t in $(TESTS); do \
		out=$$(./$$t); \
		printf '%s: %s\n' "$$t" "$$(printf '%s' "$$out" | tail -n 1)"; \
		printf '%s' "$$out" | grep -q "0 test(s) failed" || fail=1; \
	done; \
	exit $$fail

clean:
	rm -f $(TESTS) smoke
