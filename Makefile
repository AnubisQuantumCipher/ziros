.PHONY: build test audit bench demo doctor metal-doctor clean

build:
	./zkf-build.sh --release

test:
	./zkf-build.sh test --workspace --all-targets --no-fail-fast
	python3 -m unittest discover -s scripts/tests -p 'test_*.py'

audit:
	./scripts/run_builtin_example_audits.sh

bench:
	cargo bench --workspace

demo:
	./zkf-build.sh --release -p zkf-cli
	./target-local/release/zkf-cli demo --out target-local/demo

doctor:
	./zkf-build.sh --release -p zkf-cli
	./target-local/release/zkf-cli doctor

metal-doctor:
	./zkf-build.sh --release -p zkf-cli
	./target-local/release/zkf-cli metal-doctor

clean:
	cargo clean
	rm -rf target target-local dist release-artifacts release-bundles
