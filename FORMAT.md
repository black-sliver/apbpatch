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


## v4 and newer

ZIP file containing game specific files and an `archipelago.json` with at least

```json
{
    "game": "[name of the game]",
    "compatible_version": 4,
    "version": 4
}
```

The JSON file should be deflate compressed.


### v5

JSON contains `"patch_file_ending": ".extension"` that corresponds to the
original patch output filename. Useful if a single game can generate two
different patches.


#### ROM-based games using "DeltaPatch" (bsdiff)

JSON also contains
* `"base_checksum": "[hex string of md5 of vanilla file]"`
* `"result_file_ending": ".extension"`

ZIP file also contains
* `delta.bsdiff4` file that is the diff between original and randomized ROM

The bsdiff should ideally be stored (not compressed).


#### ROM-based games using zpf

ZIP file also contains
* a `.zpf` file that is to be applied using ZPF tool


### v6

JSON may contain `"procedure": ...` to descibe how to apply the patch.
* If procedure is absent or null, behavior is like in v5.
* If procedure is a string `"custom"` that means the steps neccessary to
  apply the patch are defined per game and not specified here.
  This is a custom APPatch, neither APDeltaPatch nor APProcedurePatch.
* Otherwise procedure has to be an array of tuples `[step, args]`,
  where args is an array, i.e. `[["apply_bsdiff4", ["delta.bsdiff4"]]]`.
  This means it's an
  [APProcedurePatch](https://github.com/ArchipelagoMW/Archipelago/pull/2536)

JSON may contain `"custom_version"` that is an integer to differentiate between
multiple custom handlers for the same game. For now, it is up to the handler to
use or ignore `custom_version`.


## Version detection

To differentiate between v4+ and v3- compare magic sequence:
* xz steam starts with FD 37 7A 58 5A 00
* zip file starts with "PK"

The actual (numerical) version is then part of the yaml or json.
