#![allow(unused)]

use vstd::prelude::*;

verus! {

pub enum Visibility {
    Public,
    Private,
    Constant,
}

pub struct Symbol {
    pub visibility: Visibility,
    pub assigned: bool,
}

pub open spec fn can_expose(symbol: Symbol) -> bool {
    match symbol.visibility {
        Visibility::Public => true,
        Visibility::Private => symbol.assigned,
        Visibility::Constant => true,
    }
}

proof fn private_unassigned_cannot_expose(symbol: Symbol)
    requires
        matches!(symbol.visibility, Visibility::Private),
        symbol.assigned == false,
    ensures
        can_expose(symbol) == false,
{
}

proof fn public_symbol_can_expose(symbol: Symbol)
    requires
        matches!(symbol.visibility, Visibility::Public),
    ensures
        can_expose(symbol) == true,
{
}

}
