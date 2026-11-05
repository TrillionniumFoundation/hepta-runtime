// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

// Compile against the unmodified ggml headers pinned in the companion document.
// This only observes C++ sizeof constants; it never loads or runs a model.
#include <cstdio>
#include "ggml.h"
#define GGML_COMMON_DECL_CPP
#include "ggml-common.h"

static bool first = true;
static void row(const char * name, ggml_type type, unsigned int elements, size_t bytes) {
    std::printf("%s{\"name\":\"%s\",\"type_id\":%d,\"block_elements\":%u,\"block_bytes\":%zu}",
        first ? "" : ",", name, static_cast<int>(type), elements, bytes);
    first = false;
}

int main() {
    std::puts("[");
    row("F32", GGML_TYPE_F32, 1, sizeof(float));
    row("F16", GGML_TYPE_F16, 1, sizeof(ggml_fp16_t));
    row("Q4_0", GGML_TYPE_Q4_0, QK4_0, sizeof(block_q4_0));
    row("Q4_1", GGML_TYPE_Q4_1, QK4_1, sizeof(block_q4_1));
    row("Q5_0", GGML_TYPE_Q5_0, QK5_0, sizeof(block_q5_0));
    row("Q5_1", GGML_TYPE_Q5_1, QK5_1, sizeof(block_q5_1));
    row("Q8_0", GGML_TYPE_Q8_0, QK8_0, sizeof(block_q8_0));
    row("I32", GGML_TYPE_I32, 1, sizeof(int32_t));
    row("I64", GGML_TYPE_I64, 1, sizeof(int64_t));
    row("F64", GGML_TYPE_F64, 1, sizeof(double));
    row("IQ1_M", GGML_TYPE_IQ1_M, QK_K, sizeof(block_iq1_m));
    row("BF16", GGML_TYPE_BF16, 1, sizeof(ggml_bf16_t));
    row("TQ1_0", GGML_TYPE_TQ1_0, QK_K, sizeof(block_tq1_0));
    row("TQ2_0", GGML_TYPE_TQ2_0, QK_K, sizeof(block_tq2_0));
    row("MXFP4", GGML_TYPE_MXFP4, QK_MXFP4, sizeof(block_mxfp4));
    row("NVFP4", GGML_TYPE_NVFP4, QK_NVFP4, sizeof(block_nvfp4));
    row("Q1_0", GGML_TYPE_Q1_0, QK1_0, sizeof(block_q1_0));
    row("Q2_0", GGML_TYPE_Q2_0, QK2_0, sizeof(block_q2_0));
    std::puts("]");
}
