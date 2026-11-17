#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import importlib.util,sys
from async_build_common import require,pin,raw,files
ROOT=Path(__file__).resolve().parent.parent/"fixture"
spec=importlib.util.spec_from_file_location("duplex_frozen_compose",ROOT/"source/compose.py")
composer=importlib.util.module_from_spec(spec);spec.loader.exec_module(composer)
def compose(text):return composer.compose(text)
def install(builder):return composer.install(builder)
def evidence():
    return dict(schema="hepta.publication.duplex.native-boundary.v1",source_files=files(ROOT),
        fixed_socket=5,input_pipe_fds=[7,9],output_pipe_fds=[8,10],sessions=2,
        shared_configuration=True,shared_filesystem_hub=True,shared_text_hub=True,
        shared_bellman_port=True,shared_publication_pool=True,
        independent_engine_registry_cache_workdir=True,ordinary_framing_preserved=True,
        close_session_does_not_destroy_shared_runtime=True,bellman_multisession_delivery_qualified=False,
        full_async=False,full_sdk=False)
