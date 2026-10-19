CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2

INC_DIR   := include
SRC_DIR   := src
TEST_DIR  := tests
BUILD_DIR := build

CIPHERS  := AES Blowfish Twofish DES Serpent
LIB_SRCS := $(SRC_DIR)/BlockCipher.cpp $(SRC_DIR)/Padding.cpp $(CIPHERS:%=$(SRC_DIR)/%.cpp)
TESTS    := $(CIPHERS:%=%Test) GenericModeTest
BINS     := $(addprefix $(BUILD_DIR)/,$(TESTS))
DEPS     := $(wildcard $(INC_DIR)/block/*.h $(SRC_DIR)/*.h)

.PHONY: all test clean

all: $(BINS)

$(BUILD_DIR):
	mkdir -p $@

# Every test links the whole library; unused ciphers cost nothing and adding a
# cipher here needs no new rule.
$(BUILD_DIR)/%: $(TEST_DIR)/%.cpp $(LIB_SRCS) $(DEPS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) $< $(LIB_SRCS) -o $@

test: all
	@fail=0; \
	for t in $(TESTS); do \
		out=$$(./$(BUILD_DIR)/$$t); \
		printf '%s: %s\n' "$$t" "$$(printf '%s' "$$out" | tail -n 1)"; \
		printf '%s' "$$out" | grep -q "0 test(s) failed" || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf $(BUILD_DIR)
