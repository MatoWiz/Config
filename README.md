# Config

Huawei DN8245V-56 configuration decryption helper.

## Usage

```bash
python3 -m pip install -r requirements.txt
python3 decrypt_huawei.py /home/runner/work/Config/Config/hw_ctree.xml.html --output decrypted_output.bin
```

The script:
- strips the proprietary 12-byte Huawei header (default)
- tries common DN8245V AES keys and IVs
- optionally derives salted key variants from a MAC/serial hint (`--mac`)
- attempts second-pass `gzip`, `zlib`, or raw `deflate` decompression
- prints a preview and can save the best candidate with `--output`

Use `--help` to view all options.
