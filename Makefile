all: check docs

check:
	# Clippy checks
	RUST_BACKTRACE=full cargo clippy --color always -- \
				   --no-deps \
				   --allow clippy::verbose_bit_mask \
				   --allow clippy::print_with_newline \
				   --allow clippy::write_with_newline \
				   --allow clippy::module_name_repetitions \
				   --allow clippy::missing_errors_doc \
				   --deny  missing_docs \
				   --deny  clippy::missing_docs_in_private_items \
				   --deny  clippy::pedantic \
				   --allow clippy::struct_excessive_bools \
				   --allow clippy::redundant_field_names \
				   --allow clippy::must_use_candidate \
				   --allow clippy::manual_flatten

docs: check
	# Documentation build regardless of arch
	cargo doc --no-deps
