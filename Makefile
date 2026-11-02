# Build from the project root, as expected by the firmware makefile.
.PHONY: all crypto-firmware test
all: crypto-firmware
crypto-firmware:
	$(MAKE) -f crypto_standalone/Makefile
test:
	python3 tests/test_crypto.py
	python3 tests/test_crypto_request.py
	python3 tests/test_crypto_scratch.py
	python3 tests/test_poly_parallel.py
	sh tests/test_crypto_qemu.sh
