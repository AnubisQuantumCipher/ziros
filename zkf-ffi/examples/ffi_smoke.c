#include <stdbool.h>
#include <stdio.h>

#include "zkf.h"

static int fail(const char *step) {
  const char *message = zkf_last_error_message();
  fprintf(stderr, "%s failed: %s\n", step, message ? message : "(unknown)");
  return 1;
}

int main(void) {
  const char *mul_expr =
      "{\"op\":\"mul\",\"args\":[{\"op\":\"signal\",\"args\":\"x\"},{\"op\":\"signal\",\"args\":\"y\"}]}";
  const char *product_expr = "{\"op\":\"signal\",\"args\":\"product\"}";
  const char *inputs_json = "{\"x\":\"3\",\"y\":\"7\"}";

  ZkfProgramBuilderHandle *builder = zkf_program_builder_new("ffi_multiply", "goldilocks");
  if (builder == NULL) {
    return fail("zkf_program_builder_new");
  }

  if (zkf_program_builder_private_input(builder, "x") != 0) {
    return fail("zkf_program_builder_private_input(x)");
  }
  if (zkf_program_builder_private_input(builder, "y") != 0) {
    return fail("zkf_program_builder_private_input(y)");
  }
  if (zkf_program_builder_public_output(builder, "product") != 0) {
    return fail("zkf_program_builder_public_output(product)");
  }
  if (zkf_program_builder_add_assignment_json(builder, "product", mul_expr) != 0) {
    return fail("zkf_program_builder_add_assignment_json");
  }
  if (zkf_program_builder_constrain_equal_json(builder, product_expr, mul_expr) != 0) {
    return fail("zkf_program_builder_constrain_equal_json");
  }

  ZkfProgramHandle *program = zkf_program_builder_build(builder);
  if (program == NULL) {
    return fail("zkf_program_builder_build");
  }

  ZkfCompiledProgramHandle *compiled = zkf_compile(program, "plonky3");
  if (compiled == NULL) {
    return fail("zkf_compile");
  }

  ZkfProofArtifactHandle *artifact = zkf_prove(program, inputs_json, "plonky3");
  if (artifact == NULL) {
    return fail("zkf_prove");
  }

  if (!zkf_verify(program, artifact, "plonky3")) {
    return fail("zkf_verify");
  }

  puts("ffi smoke test passed");

  zkf_free_proof_artifact(artifact);
  zkf_free_compiled_program(compiled);
  zkf_free_program(program);
  zkf_free_program_builder(builder);
  return 0;
}
