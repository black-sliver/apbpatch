# APBP Format


## v3 and older

xz compressed yaml containing at least

```yaml
game: [name of the game]
patch: [binary patch data in bsdiff4 format]
base_checksum: [hex string of md5 of vanilla file]
compatible_version: 1
version: 3
```

Difference between versions 1-3 is specific to the python patcher.


## v4

ZIP file containing game specific files and an `archipelago.json` with at least

```json
{
    "game": "[name of the game]",
    "compatible_version": 4,
    "version": 4
}
```

The JSON file should be deflate compressed.

### ROM-based games

JSON also contains `"base_checksum": "[hex string of md5 of vanilla file]"`.\
ZIP file also contains a `delta.bsdiff4` file that is the diff between
original and randomized ROM.

The bsdiff should ideally be stored (not compressed).


## Version detection

To differentiate between v4+ and v3- compare magic sequence:
* xz steam starts with FD 37 7A 58 5A 00
* zip file starts with "PK"

The actual (numerical) version is then part of the yaml or json.
