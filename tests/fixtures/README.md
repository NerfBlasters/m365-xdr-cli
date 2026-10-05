# CLI migration contracts

The initial `cli_contract.json` and `cli_errors.json` were captured from
main commit `13114bc` (xdr-cli 0.14.0, Typer 0.24.2, Click 8.5.0).

The surface covers 78 command/group entries; 188 binding cases cover required
arguments, supplied options, repeated options, and each boolean flag direction.
Callbacks were replaced before framework command construction, so no application
operations or dispatch hooks ran. The error corpus retains the production
error boundary but replaces root, group, and leaf callbacks.

Reviewed normalizations/differences:

- The two removed root completion options are excluded from the surface fixture.
  Their removal has an explicit regression test.
- Required-parameter defaults normalize to null instead of comparing Click's
  unset sentinel. Callback value equivalence is tested separately.
- Synthetic input/output paths normalize to markers for platform independence.
- 33 positional-argument help descriptions now populate Click's help metadata.
  Their text is preserved from the original declarations; Typer's realized
  argument metadata did not retain that attribute with Click 8.5.
- Enum defaults are normalized to their accepted CLI values.
- The `\b` markers preserving existing help paragraphs' line breaks are
  excluded from whitespace-normalized help content.

Binding values and structured parser fields retain their baseline values.
Typer duplicated Click's “Did you mean” hint for misspelled commands; the
comparison removes only that repeated phrase in human-readable messages.
The raw baseline fixture retains the duplicate as captured.
Help framing is intentionally not compared byte-for-byte. To regenerate, run
`XDR_REGENERATE_CLI_CONTRACT=1 pytest tests/test_cli_contract.py -q` and review
every change; never regenerate solely to resolve a failing comparison.

After conversion, surface-only argument help fields were populated from the
original declarations and enum defaults normalized. The binding cases were not
regenerated for these adjustments; independent review recaptured all 188 from
untouched main and confirmed equality. Rendered help is tested separately.

The error corpus was expanded from 8 to 25 cases after review. The additional
17 records were captured independently using the untouched Typer baseline,
with inert callbacks and the production parser/error boundary.
