"""Immutable public identities; tensor hashes are BF16 bytes, not float32."""

SOURCE_REPOSITORY = "RikiyaT/lm_understand-logs"
SOURCE_COMMIT = "4d09ba6d6a7e891dd8063974dfe81b3d78e3494f"
BASE_REPOSITORY = "Qwen/Qwen3.5-0.8B"
BASE_REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
SOURCE_PREFIX = "exp8_math/runs/p50c"
EXPECTED_TENSORS = {
    "model.language_model.layers.15.mlp.down_proj.weight": {
        "shape": [1024, 3584],
        "base_sha256": "ef60d2c687bab19464dca9c8bfd7777e46ad226df0c9e25643b0bab04b5a1cca",
        "edited_sha256": "82e2d733ea64feaeb4af93a1e065641d3df98b494a8b7576ef2f52e90fe2ee53",
        "changed_entries": 65260,
        "changed_columns": 64,
    },
    "model.language_model.layers.19.mlp.down_proj.weight": {
        "shape": [1024, 3584],
        "base_sha256": "638eedeb701b94aa861f4438e615c07ec6c60ee703db1bfee2de577bb6498c3e",
        "edited_sha256": "8ef3c61bc36af113ad58e89dbb0a4a14dcba5a45cb750c15ab515c82ddd12eb2",
        "changed_entries": 64928,
        "changed_columns": 64,
    },
}
