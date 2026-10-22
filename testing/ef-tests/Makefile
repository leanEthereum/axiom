# Downloads the consensus spec test vectors into testing/vectors.
#
#   make -C testing/ef-tests
#
# The versions track the latest consensus-specs release.

CONSENSUS_SPECS_VERSION ?= v1.7.0-beta.4
BLS_TESTS_VERSION ?= v0.1.2
CKZG_VERSION ?= v2.1.8

VECTORS := ../vectors
SPEC_DIR := $(VECTORS)/consensus-spec-tests
BLS_DIR := $(VECTORS)/bls12-381-tests
KZG_DIR := $(VECTORS)/kzg

SPEC_URL := https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_VERSION)
BLS_URL := https://github.com/ethereum/bls12-381-tests/releases/download/$(BLS_TESTS_VERSION)
CKZG_URL := https://github.com/ethereum/c-kzg-4844/archive/refs/tags/$(CKZG_VERSION).tar.gz

.PHONY: all

all: $(SPEC_DIR) $(BLS_DIR) $(KZG_DIR)

$(SPEC_DIR):
	mkdir -p $@
	for preset in general minimal mainnet; do \
		curl --location --fail --silent --show-error $(SPEC_URL)/$$preset.tar.gz | tar -xz -C $@; \
	done

$(BLS_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(BLS_URL)/bls_tests_yaml.tar.gz | tar -xz -C $@

$(KZG_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(CKZG_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/tests'
