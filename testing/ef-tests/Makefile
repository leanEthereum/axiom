# Downloads every reference vector set into testing/vectors.
#
#   make -C testing/ef-tests
#
# Each source is pinned to a release or a commit, so a run is reproducible.

CONSENSUS_SPECS_VERSION ?= v1.7.0-beta.4
BLS_TESTS_VERSION ?= v0.1.2
CKZG_VERSION ?= v2.1.8
# The general suite of this release is the last to ship ssz_generic.
# It merkleizes progressive types with the subtrees on the left, as EIP-7916 now specifies.
GENERAL_SPECS_VERSION ?= v1.7.0-alpha.13
WYCHEPROOF_COMMIT ?= 7a325932231bd7a724c791c8b0d65ea4d6d2f435
JSON_SUITE_COMMIT ?= 1ef36fa01286573e846ac449e8683f8833c5b26a
MULTIBASE_COMMIT ?= d7406cdea189b82a0b3937f5737b440f5fa92f92
# NIST and the Keccak team publish these archives unversioned, so each is pinned by its SHA-256.
AES_KAT_SHA256 ?= a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60
GCM_KAT_SHA256 ?= f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
KECCAK_KAT_SHA256 ?= af92d22d23527a0d168a6bbe70b28c840a43bba5bcea828a6d9a5e7ad79378ce
SHA3_KAT_SHA256 ?= cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
SHAKE_KAT_SHA256 ?= debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7
# The beacon node API's OpenAPI definition, which the API conformance test walks.
BEACON_APIS_COMMIT ?= 79b9b05e354da4f80d8f18879871af6f0068108d

VECTORS := ../vectors
SPEC_DIR := $(VECTORS)/consensus-spec-tests
BLS_DIR := $(VECTORS)/bls12-381-tests
KZG_DIR := $(VECTORS)/kzg
GENERAL_DIR := $(VECTORS)/consensus-spec-general
WYCHEPROOF_DIR := $(VECTORS)/wycheproof
JSON_SUITE_DIR := $(VECTORS)/json-test-suite
MULTIBASE_DIR := $(VECTORS)/multibase
CAVP_DIR := $(VECTORS)/nist-cavp
KECCAK_KAT_DIR := $(VECTORS)/keccak-kat
SHA3_KAT_DIR := $(VECTORS)/nist-sha3
SPEC_CONFIG_DIR := $(VECTORS)/consensus-specs
BEACON_APIS_DIR := $(VECTORS)/beacon-apis

SPEC_URL := https://github.com/ethereum/consensus-specs/releases/download/$(CONSENSUS_SPECS_VERSION)
BLS_URL := https://github.com/ethereum/bls12-381-tests/releases/download/$(BLS_TESTS_VERSION)
CKZG_URL := https://github.com/ethereum/c-kzg-4844/archive/refs/tags/$(CKZG_VERSION).tar.gz
GENERAL_URL := https://github.com/ethereum/consensus-specs/releases/download/$(GENERAL_SPECS_VERSION)/general.tar.gz
WYCHEPROOF_URL := https://github.com/C2SP/wycheproof/archive/$(WYCHEPROOF_COMMIT).tar.gz
JSON_SUITE_URL := https://github.com/nst/JSONTestSuite/archive/$(JSON_SUITE_COMMIT).tar.gz
MULTIBASE_URL := https://github.com/multiformats/multibase/archive/$(MULTIBASE_COMMIT).tar.gz
CAVP_URL := https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents
AES_KAT_URL := $(CAVP_URL)/aes/KAT_AES.zip
GCM_KAT_URL := $(CAVP_URL)/mac/gcmtestvectors.zip
KECCAK_KAT_URL := https://keccak.team/obsolete/KeccakKAT-3.zip
SHA3_KAT_URL := $(CAVP_URL)/sha3/sha-3bytetestvectors.zip
SHAKE_KAT_URL := $(CAVP_URL)/sha3/shakebytetestvectors.zip
SPEC_SOURCE_URL := https://github.com/ethereum/consensus-specs/archive/refs/tags/$(CONSENSUS_SPECS_VERSION).tar.gz
BEACON_APIS_URL := https://github.com/ethereum/beacon-APIs/archive/$(BEACON_APIS_COMMIT).tar.gz

.PHONY: all

all: $(SPEC_DIR) $(BLS_DIR) $(KZG_DIR) $(GENERAL_DIR) $(WYCHEPROOF_DIR) $(JSON_SUITE_DIR) $(MULTIBASE_DIR) \
	$(CAVP_DIR) $(KECCAK_KAT_DIR) $(SHA3_KAT_DIR) $(SPEC_CONFIG_DIR) $(BEACON_APIS_DIR)

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

$(GENERAL_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(GENERAL_URL) | tar -xz -C $@

$(WYCHEPROOF_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(WYCHEPROOF_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/testvectors_v1'

$(JSON_SUITE_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(JSON_SUITE_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/test_parsing'

$(MULTIBASE_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(MULTIBASE_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/tests'

# The AES-128 known answers of AESAVS and the AES-128 tests of GCMVS.
# The archives land in a scratch directory, renamed into place only once verified.
$(CAVP_DIR):
	rm -rf $@.tmp && mkdir -p $@.tmp/aes $@.tmp/gcm
	curl --location --fail --silent --show-error $(AES_KAT_URL) -o $@.tmp/aes.zip
	curl --location --fail --silent --show-error $(GCM_KAT_URL) -o $@.tmp/gcm.zip
	echo "$(AES_KAT_SHA256)  $@.tmp/aes.zip" | sha256sum --check --quiet
	echo "$(GCM_KAT_SHA256)  $@.tmp/gcm.zip" | sha256sum --check --quiet
	unzip -q $@.tmp/aes.zip 'ECB*128.rsp' -d $@.tmp/aes
	unzip -q $@.tmp/gcm.zip gcmEncryptExtIV128.rsp gcmDecrypt128.rsp -d $@.tmp/gcm
	rm $@.tmp/aes.zip $@.tmp/gcm.zip
	mv $@.tmp $@

# The Keccak team's round 3 known answers for Keccak-256.
$(KECCAK_KAT_DIR):
	rm -rf $@.tmp && mkdir -p $@.tmp
	curl --location --fail --silent --show-error $(KECCAK_KAT_URL) -o $@.tmp/kat.zip
	echo "$(KECCAK_KAT_SHA256)  $@.tmp/kat.zip" | sha256sum --check --quiet
	unzip -q -j $@.tmp/kat.zip 'KeccakKAT/*MsgKAT_256.txt' -d $@.tmp
	rm $@.tmp/kat.zip
	mv $@.tmp $@

# The SHA3VS byte-oriented known answers for SHA-3 and SHAKE, from FIPS 202 validation.
$(SHA3_KAT_DIR):
	rm -rf $@.tmp && mkdir -p $@.tmp
	curl --location --fail --silent --show-error $(SHA3_KAT_URL) -o $@.tmp/sha3.zip
	curl --location --fail --silent --show-error $(SHAKE_KAT_URL) -o $@.tmp/shake.zip
	echo "$(SHA3_KAT_SHA256)  $@.tmp/sha3.zip" | sha256sum --check --quiet
	echo "$(SHAKE_KAT_SHA256)  $@.tmp/shake.zip" | sha256sum --check --quiet
	unzip -q $@.tmp/sha3.zip -d $@.tmp
	unzip -q $@.tmp/shake.zip -d $@.tmp
	rm $@.tmp/sha3.zip $@.tmp/shake.zip
	mv $@.tmp $@

# The configuration and preset files of the pinned release, which the config route must echo.
$(SPEC_CONFIG_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(SPEC_SOURCE_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/configs' '*/presets'

# The beacon node API definition: the index file, the routes, and the types they name.
$(BEACON_APIS_DIR):
	mkdir -p $@
	curl --location --fail --silent --show-error $(BEACON_APIS_URL) \
		| tar -xz -C $@ --strip-components=1 --wildcards '*/beacon-node-oapi.yaml' '*/apis' '*/types' '*/params'
