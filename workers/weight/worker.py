#!/usr/bin/env python3
"""Dedicated CPU PyTorch worker. Every stdout line is a protocol response."""
import os
import sys

thread_keys = ("OPENBLAS_NUM_THREADS", "GOTO_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")
owner_caps = [int(os.environ[k]) for k in thread_keys
              if os.environ.get(k, "").isdigit() and 1 <= int(os.environ[k]) <= 8]
thread_cap = min(owner_caps) if owner_caps else 2
for key in thread_keys:
    os.environ[key] = str(thread_cap)
os.environ.update(OMP_WAIT_POLICY="PASSIVE", TOKENIZERS_PARALLELISM="false",
                  HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", USE_TF="0")

from weight_runtime.transport import main

if __name__ == "__main__":
    sys.exit(main(__file__))
