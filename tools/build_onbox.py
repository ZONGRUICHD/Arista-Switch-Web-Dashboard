#!/usr/bin/env python3
"""Build the canonical web assets into the EOS single-file application.

The output is deterministic: it contains no timestamps and normalizes all source
files to LF line endings. Run without arguments to update the embedded asset;
use --check in CI to fail when the generated block is out of date.
"""

import argparse
import base64
import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "web"
DEFAULT_TARGET = ROOT / "onbox" / "arista7050_web.py"
BEGIN_MARKER = "# BEGIN GENERATED WEB ASSET"
END_MARKER = "# END GENERATED WEB ASSET"


def normalized_text(path):
    """Read UTF-8 text with stable newlines and exactly one trailing newline."""
    value = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return value.rstrip("\n") + "\n"


def csp_hash(content):
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def compose_html(source_dir):
    template = normalized_text(source_dir / "index.html")
    css = normalized_text(source_dir / "styles.css")
    script = normalized_text(source_dir / "app.js")

    style_tag = '<link rel="stylesheet" href="/styles.css" />'
    script_tag = '<script src="/app.js"></script>'
    if template.count(style_tag) != 1:
        raise ValueError("web/index.html must contain exactly one canonical stylesheet link.")
    if template.count(script_tag) != 1:
        raise ValueError("web/index.html must contain exactly one canonical script tag.")

    style_payload = "\n" + css
    script_payload = "\n" + script
    html = template.replace(style_tag, "<style>%s</style>" % style_payload)
    html = html.replace(script_tag, "<script>%s</script>" % script_payload)
    html = html.rstrip("\n") + "\n"
    if '"""' in html:
        raise ValueError('Generated HTML contains a Python raw triple-quote delimiter (""").')
    return html, csp_hash(style_payload), csp_hash(script_payload)


def generated_block(html, style_hash, script_hash):
    return "\n".join(
        [
            BEGIN_MARKER,
            'INDEX_HTML = r"""%s"""' % html,
            END_MARKER,
        ]
    )


def locate_generated_span(target_text):
    marked = re.search(
        r"(?ms)^%s\n.*?^%s$" % (re.escape(BEGIN_MARKER), re.escape(END_MARKER)),
        target_text,
    )
    if marked:
        return marked.span()

    legacy = re.search(
        r'(?ms)^INDEX_HTML = r?""".*?"""(?=\n{2,}class Handler\b)',
        target_text,
    )
    if legacy:
        return legacy.span()
    raise ValueError("Could not find the generated web asset block or legacy INDEX_HTML assignment.")


def render_target(target_text, block, constants):
    start, end = locate_generated_span(target_text)
    rendered = target_text[:start] + block + target_text[end:]
    missing = []
    for name, value in constants.items():
        pattern = re.compile(r'(?m)^%s = "[^"]*"$' % re.escape(name))
        matches = list(pattern.finditer(rendered))
        if len(matches) > 1:
            raise ValueError("Expected at most one %s assignment." % name)
        assignment = '%s = "%s"' % (name, value)
        if matches:
            rendered = pattern.sub(assignment, rendered, count=1)
        else:
            missing.append(assignment)
    if missing:
        marker_at = rendered.index(BEGIN_MARKER)
        rendered = rendered[:marker_at] + "\n".join(missing) + "\n" + rendered[marker_at:]
    return rendered


def main(argv=None):
    parser = argparse.ArgumentParser(description="Embed canonical web assets in the EOS Python application.")
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--check", action="store_true", help="Exit non-zero instead of writing when the target is stale.")
    args = parser.parse_args(argv)

    try:
        html, style_hash, script_hash = compose_html(args.source_dir.resolve())
        block = generated_block(html, style_hash, script_hash)
        current = normalized_text(args.target.resolve())
        expected = render_target(
            current,
            block,
            {
                "WEB_STYLE_HASH": style_hash,
                "WEB_SCRIPT_HASH": script_hash,
                "WEB_ASSET_SHA": hashlib.sha256(html.encode("utf-8")).hexdigest(),
            },
        )
    except (OSError, ValueError) as exc:
        print("build_onbox: %s" % exc, file=sys.stderr)
        return 2

    if current == expected:
        print("Embedded web asset is up to date.")
        return 0
    if args.check:
        print("Embedded web asset is stale. Run: python tools/build_onbox.py", file=sys.stderr)
        return 1

    with args.target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(expected)
    print("Updated %s (%s)." % (args.target, hashlib.sha256(html.encode("utf-8")).hexdigest()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
