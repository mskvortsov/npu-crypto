# Build from the project root, as expected by the firmware makefile.
CLANG_FORMAT ?= clang-format-22
FIRMWARE_FORMAT_SOURCES := $(wildcard npu/*.c npu/*.h)
LINUX_FORMAT_SOURCES := $(wildcard linux/*.c linux/*.h)

.PHONY: all crypto-firmware tidy tidy-firmware tidy-linux format format-check format-firmware format-linux format-check-firmware format-check-linux test
all: crypto-firmware
crypto-firmware:
	$(MAKE) -f npu/firmware.mk
tidy-firmware:
	$(MAKE) -f npu/firmware.mk tidy
tidy-linux:
	$(MAKE) -f linux/tooling.mk tidy
tidy: tidy-firmware tidy-linux
format: format-firmware format-linux
format-check: format-check-firmware format-check-linux
format-firmware:
	$(CLANG_FORMAT) -i $(FIRMWARE_FORMAT_SOURCES)
format-check-firmware:
	$(CLANG_FORMAT) --dry-run --Werror $(FIRMWARE_FORMAT_SOURCES)
format-linux:
	$(CLANG_FORMAT) -i $(LINUX_FORMAT_SOURCES)
format-check-linux:
	$(CLANG_FORMAT) --dry-run --Werror $(LINUX_FORMAT_SOURCES)
test:
	python3 tests/test_crypto.py
	python3 tests/test_crypto_request.py
	python3 tests/test_crypto_scratch.py
	python3 tests/test_poly_parallel.py
	sh tests/test_crypto_qemu.sh

.PHONY: benchmark
benchmark:
	./tools/build-kcapi-bench.sh
