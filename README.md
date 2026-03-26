# Config

Huawei DN8245V-56 configuration decryption helper.

## Usage

```bash
python3 -m pip install -r requirements.txt
python3 decrypt_huawei.py ./hw_ctree.xml \
  --serial 45475445AA037BDB \
  --mac A4:6D:A4:8D:D0:79 \
  --output decrypted_output.bin
```

The script:
- tries hardware-derived key hypotheses (SN/MAC/master-key based) plus legacy keys
- iterates a built-in list of common header offsets (or custom `--offsets`)
- tests AES-CBC with legacy IVs plus SN/MAC-derived IV hypotheses
- performs sliding decompression search in the first 128 bytes for `zlib`, `gzip`, and raw `deflate`
- prints a preview and can save the best candidate with `--output`
- fails with a non-zero exit when no high-confidence XML candidate is found

Use `--help` to view all options.
