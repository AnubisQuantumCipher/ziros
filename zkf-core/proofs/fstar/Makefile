FSTAR_BIN ?= $(shell command -v fstar.exe 2>/dev/null || command -v fstar 2>/dev/null)
PYTHON ?= python3

CACHE_DIR ?= .cache
HINT_DIR ?= .hints

REPO_ROOT := $(if $(strip $(ZKF_FSTAR_REPO_ROOT)),$(ZKF_FSTAR_REPO_ROOT),$(abspath ../../..))
REAL_REPO_ROOT := $(shell cd "$(REPO_ROOT)" && /bin/pwd -P)
HAX_PIN_FILE := HAX_PIN.toml
HAX_REV_SHORT := $(shell sed -n 's/^rev = "\(.*\)"/\1/p' "$(HAX_PIN_FILE)" | cut -c1-7)
CARGO_HAX_ROOT := $(shell find "$(HOME)/.cargo/git/checkouts" -maxdepth 5 -type d -path "*/$(HAX_REV_SHORT)/hax-lib" 2>/dev/null | head -n 1)
HAX_ROOT := $(if $(strip $(ZKF_HAX_ROOT)),$(ZKF_HAX_ROOT),$(if $(wildcard $(REPO_ROOT)/.zkf-tools/hax/src/hax/hax-lib),$(REPO_ROOT)/.zkf-tools/hax/src/hax/hax-lib,$(CARGO_HAX_ROOT)))
HAX_FSTAR_EXTRACTION := $(HAX_ROOT)/proofs/fstar/extraction
HAX_FSTAR_LIB := $(HAX_ROOT)/proof-libs/fstar
FSTAR_Z3_VERSION := $(if $(strip $(ZKF_FSTAR_Z3_VERSION)),$(ZKF_FSTAR_Z3_VERSION),4.8.5)
FSTAR_Z3_BIN := $(if $(strip $(ZKF_FSTAR_Z3_BIN)),$(ZKF_FSTAR_Z3_BIN),$(shell command -v z3-$(FSTAR_Z3_VERSION) 2>/dev/null || true))

ROOTS = ConstantTimeProofs.fst
EXTRACTED_ROOTS = extraction/Zkf_core.Proof_constant_time_bridge.fst
FULL_CHECKS = \
  $(CACHE_DIR)/Zkf_core.Proof_constant_time_bridge.fst.checked \
  $(CACHE_DIR)/ConstantTimeProofs.fst.checked

HAX_INCLUDE_FLAGS = \
  $(if $(wildcard $(HAX_FSTAR_EXTRACTION)),--include "$(HAX_FSTAR_EXTRACTION)") \
  $(if $(wildcard $(HAX_FSTAR_LIB)/core),--include "$(HAX_FSTAR_LIB)/core") \
  $(if $(wildcard $(HAX_FSTAR_LIB)/rust_primitives),--include "$(HAX_FSTAR_LIB)/rust_primitives")

FSTAR_FLAGS = --cmi \
  --warn_error -331 \
  --cache_checked_modules --cache_dir $(CACHE_DIR) \
  --already_cached "+Prims+FStar+LowStar+C+Spec.Loops+TestLib" \
  --include . \
  --include ./extraction \
  $(HAX_INCLUDE_FLAGS) \
  --z3version $(FSTAR_Z3_VERSION) \
  $(if $(strip $(FSTAR_Z3_BIN)),--smt "$(FSTAR_Z3_BIN)")

FSTAR = "$(FSTAR_BIN)" $(FSTAR_FLAGS)
FSTAR_LAX = $(FSTAR) --lax

.PHONY: all verify clean

all: verify

$(HINT_DIR):
	mkdir -p $@

$(CACHE_DIR):
	mkdir -p $@

$(CACHE_DIR)/Zkf_core.Proof_constant_time_bridge.fst.checked: $(EXTRACTED_ROOTS) | $(HINT_DIR) $(CACHE_DIR)
	$(if $(strip $(OTHERFLAGS)),$(FSTAR) $(OTHERFLAGS),$(FSTAR)) $< --hint_file $(HINT_DIR)/Zkf_core.Proof_constant_time_bridge.fst.hints

$(CACHE_DIR)/ConstantTimeProofs.fst.checked: ConstantTimeProofs.fst $(CACHE_DIR)/Zkf_core.Proof_constant_time_bridge.fst.checked | $(HINT_DIR) $(CACHE_DIR)
	$(if $(strip $(OTHERFLAGS)),$(FSTAR) $(OTHERFLAGS),$(FSTAR)) $< --hint_file $(HINT_DIR)/ConstantTimeProofs.fst.hints

verify: $(FULL_CHECKS)

clean:
	rm -rf $(CACHE_DIR) $(HINT_DIR)
