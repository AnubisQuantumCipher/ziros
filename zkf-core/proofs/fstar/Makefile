FSTAR_BIN ?= $(shell command -v fstar.exe 2>/dev/null || command -v fstar 2>/dev/null)
PYTHON ?= python3

CACHE_DIR ?= .cache
HINT_DIR ?= .hints

REPO_ROOT := $(if $(strip $(ZKF_FSTAR_REPO_ROOT)),$(ZKF_FSTAR_REPO_ROOT),$(abspath ../../..))
REAL_REPO_ROOT := $(shell cd "$(REPO_ROOT)" && /bin/pwd -P)
HAX_ROOT := $(REPO_ROOT)/.zkf-tools/hax/src/hax/hax-lib
HAX_FSTAR_EXTRACTION := $(HAX_ROOT)/proofs/fstar/extraction
HAX_FSTAR_LIB := $(HAX_ROOT)/proof-libs/fstar

ROOTS = ConstantTimeProofs.fst
EXTRACTED_ROOTS = extraction/Zkf_core.Proof_constant_time_spec.fst
FULL_CHECKS = \
  $(CACHE_DIR)/Zkf_core.Proof_constant_time_spec.fst.checked \
  $(CACHE_DIR)/ConstantTimeProofs.fst.checked

FSTAR_FLAGS = --cmi \
  --warn_error -331 \
  --cache_checked_modules --cache_dir $(CACHE_DIR) \
  --already_cached "+Prims+FStar+LowStar+C+Spec.Loops+TestLib" \
  --include . \
  --include ./extraction \
  --include "$(HAX_FSTAR_EXTRACTION)" \
  --include "$(HAX_FSTAR_LIB)/core" \
  --include "$(HAX_FSTAR_LIB)/rust_primitives"

FSTAR = "$(FSTAR_BIN)" $(FSTAR_FLAGS)
FSTAR_LAX = $(FSTAR) --lax

.PHONY: all verify clean

all: verify

$(HINT_DIR):
	mkdir -p $@

$(CACHE_DIR):
	mkdir -p $@

$(CACHE_DIR)/Zkf_core.Proof_constant_time_spec.fst.checked: $(EXTRACTED_ROOTS) | $(HINT_DIR) $(CACHE_DIR)
	$(if $(strip $(OTHERFLAGS)),$(FSTAR) $(OTHERFLAGS),$(FSTAR)) $< --hint_file $(HINT_DIR)/Zkf_core.Proof_constant_time_spec.fst.hints

$(CACHE_DIR)/ConstantTimeProofs.fst.checked: ConstantTimeProofs.fst $(CACHE_DIR)/Zkf_core.Proof_constant_time_spec.fst.checked | $(HINT_DIR) $(CACHE_DIR)
	$(if $(strip $(OTHERFLAGS)),$(FSTAR) $(OTHERFLAGS),$(FSTAR)) $< --hint_file $(HINT_DIR)/ConstantTimeProofs.fst.hints

verify: $(FULL_CHECKS)

clean:
	rm -rf $(CACHE_DIR) $(HINT_DIR)
