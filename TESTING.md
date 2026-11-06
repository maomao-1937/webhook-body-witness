# Testing

Run `python -B -m unittest discover -s tests -v` in this source directory. The initial run failed before the CLI existed. The completed version passed seven tests under Windows Python 3.11.15.

Tests check the official synthetic vector, exact key bytes, malformed header endings, mismatching captures, empty bodies, caps, input immutability, argument checks before filesystem access, and a real closed stdout pipe.

The native namespace regression checks dot segments and trailing dots in every input argument before any filesystem access.

`checks.json` lists runnable examples for a matching capture, a mismatching capture and invalid usage.
