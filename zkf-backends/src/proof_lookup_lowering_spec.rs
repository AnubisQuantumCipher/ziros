#![allow(dead_code)]

/// Maximum table size for the proof-facing selector/value-table lowering path.
const MAX_SELECTOR_VALUE_TABLE_ROWS: usize = 256;

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpecSupportedLookupLoweringPath {
    SelectorValueTable,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LookupLoweringSurface {
    pub supported_path: SpecSupportedLookupLoweringPath,
    pub input_count: usize,
    pub output_count: usize,
    pub table_rows: usize,
    pub table_columns: usize,
    pub selector_count: usize,
    pub boolean_constraint_count: usize,
    pub equality_constraint_count: usize,
    pub output_binding_count: usize,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn lookup_lowering_surface_supported(
    input_count: usize,
    table_rows: usize,
    table_columns: usize,
) -> bool {
    table_rows != 0 && table_rows <= MAX_SELECTOR_VALUE_TABLE_ROWS && input_count <= table_columns
}

#[cfg_attr(hax, hax_lib::include)]
pub fn lookup_lowering_output_binding_count(
    input_count: usize,
    output_count: usize,
    table_columns: usize,
) -> usize {
    output_count.min(table_columns.saturating_sub(input_count))
}

#[cfg_attr(hax, hax_lib::include)]
pub fn lookup_lowering_equality_constraint_count(
    input_count: usize,
    output_count: usize,
    table_columns: usize,
) -> usize {
    1 + input_count + lookup_lowering_output_binding_count(input_count, output_count, table_columns)
}

#[cfg_attr(hax, hax_lib::include)]
pub fn supported_lookup_lowering_surface(
    input_count: usize,
    output_count: usize,
    table_rows: usize,
    table_columns: usize,
) -> Option<LookupLoweringSurface> {
    if lookup_lowering_surface_supported(input_count, table_rows, table_columns) {
        Some(LookupLoweringSurface {
            supported_path: SpecSupportedLookupLoweringPath::SelectorValueTable,
            input_count,
            output_count,
            table_rows,
            table_columns,
            selector_count: table_rows,
            boolean_constraint_count: table_rows,
            equality_constraint_count: lookup_lowering_equality_constraint_count(
                input_count,
                output_count,
                table_columns,
            ),
            output_binding_count: lookup_lowering_output_binding_count(
                input_count,
                output_count,
                table_columns,
            ),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LookupLoweringSurface, SpecSupportedLookupLoweringPath,
        lookup_lowering_equality_constraint_count, lookup_lowering_output_binding_count,
        lookup_lowering_surface_supported, supported_lookup_lowering_surface,
    };

    #[test]
    fn supported_selector_value_table_surface_carries_shape_counts() {
        assert!(lookup_lowering_surface_supported(1, 4, 2));
        assert_eq!(lookup_lowering_output_binding_count(1, 3, 2), 1);
        assert_eq!(lookup_lowering_equality_constraint_count(1, 3, 2), 3);
        assert_eq!(
            supported_lookup_lowering_surface(1, 3, 4, 2),
            Some(LookupLoweringSurface {
                supported_path: SpecSupportedLookupLoweringPath::SelectorValueTable,
                input_count: 1,
                output_count: 3,
                table_rows: 4,
                table_columns: 2,
                selector_count: 4,
                boolean_constraint_count: 4,
                equality_constraint_count: 3,
                output_binding_count: 1,
            })
        );
        assert_eq!(supported_lookup_lowering_surface(3, 0, 4, 2), None);
    }
}
