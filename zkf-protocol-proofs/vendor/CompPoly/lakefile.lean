import Lake

open System Lake DSL

package CompPoly where version := v!"0.1.0"

require "leanprover-community" / mathlib @ git "v4.28.0"

require ExtTreeMapLemmas from "../ExtTreeMapLemmas"

@[default_target]
lean_lib CompPoly
