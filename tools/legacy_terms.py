#!/usr/bin/env python3
"""Find every reference to the classic card-stack product's names (and the
related legacy terms) in tracked files and in commit messages, and sort each
one into what to do about it.

    tools/legacy_terms.py audit [--csv out.csv] [--md out.md] [--commits]
    tools/legacy_terms.py check

`audit` lists every match with its file, line and column, the term, a
category and a disposition. `check` exits non-zero if any match is still
marked `rewrite` or `review`, so CI can keep new references out of prose,
comments and identifiers while leaving the ones that must stay alone.

Dispositions:

- rewrite: prose, comments, identifiers and interface text; these get the
  neutral vocabulary (classic stack, xTalk, external command, ...).
- retain: references that must stay for the program to keep working or for
  legal reasons: file-format signatures, script keywords that old stacks
  use, the trademark notice, third-party names and titles, test fixtures,
  paths to data that isn't in git, and today's platform names (macOS).
- review: a string literal in code that hasn't been looked at yet.

A line holding the marker `legacy-compat` is retained on purpose: the
marker says why it has to stay. `legacy-terms:ignore` marks a false
positive (the fruit in a test stack). In Markdown, the region between
`<!-- legacy-terms:allow -->` and `<!-- /legacy-terms:allow -->` is the
one place the original names are spelled out (the compatibility and
trademark note).
"""

import csv
import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Term -> regex. Order matters: longer, more specific forms first; a span
# claimed by one term isn't matched again by a later one.
TERMS = [
    ('HyperCardPreview', r'HyperCard(?:Preview|Common)'),
    ('HyperCard', r'(?i)hyper[ _-]?card'),
    ('HyperTalk', r'(?i)hyper[ _-]?talk'),
    ('hc241', r'(?i)\bhc ?2(?:\.?\d)*\b|hc241|HC241'),
    ('XCMD', r'(?i)xcmds?'),
    ('XFCN', r'(?i)xfcns?'),
    ('STAK', r'\bSTAK\b'),
    ('WILD', r'\bWILD\b'),
    ('WildCard', r'\bWildCard\b'),
    ('SuperCard', r'(?i)\bsupercard\b'),
    ('ResEdit', r'(?i)\bresedit\b'),
    ('Bill Atkinson', r'\b(?:Bill )?Atkinson\b'),
    ('Dan Winkler', r'\b(?:Dan )?Winkler\b'),
    ('Apple Computer', r'\bApple Computer\b'),
    ('Apple', r'(?i)\bapple(?=\b|_|[A-Z])'),
    ('Macintosh', r'\bMacintosh\b'),
    ('Mac OS', r'\b(?:classic )?Mac ?OS\b'),
    ('macOS', r'\bmacOS\b|\bmacos\b'),
    ('Mac', r'\bMac\b'),
]
TERM_RES = [(name, re.compile(rx)) for name, rx in TERMS]

FIXTURE = re.compile(r'^(examples/|tests/(?!.*\.rs$)|FIX_STEPS\.tsv$|Cargo\.lock$|'
                     r'src/import/[^/]*icons\.txt$|src/model/tour_)')
LEGAL = {'LICENSE'}
GENERATED_LISTINGS = {'WORKING_STACKS.md', 'CLASSIC_241_STACKS.md', 'HYPERCARD_241_STACKS.md'}

# Names of formats, codes and protocols: these are what the files and
# scripts actually say, so they stay.
FORMAT_IDS = re.compile(
    r"\bSTAK\b|\bWILD\b|[Aa]pple ?[Ee]vents?|AppleScript|Apple ?Single|Apple ?Double|"
    r"apple_entry|Apple Data Compression|Mac ?Roman|x-mac-|MacBinary|Macintosh HD|"
    r"Apple_HFS|Apple_Developer_Discs\S*|APPLE_(?:SINGLE|DOUBLE)|apple_(?:single|double)|Apple ?Link|Apple ?Talk|Apple Stacks|Apple II|Apple [Mm]enu|Apple Pie|\bapple\b(?= ?(?:menu|pie|key))|selectLineXCMD")
MODERN = re.compile(
    r"Apple [Ss]ilicon|/MacOS\b|-//Apple//|apple\.com|macOS|macos|apple-darwin|Apple Silicon|Apple's (?:command line|developer) tools|"
    r"Apple Developer|notari[sz]|Xcode|App Store|AVFoundation|\bMac\b(?! ?OS)|"
    r"make_mac_app|\.app\b|Gatekeeper")
THIRD_PARTY = re.compile(r"(?:Sp)?Inside Macintosh|Macintosh (?:LC|Classic|II\w*|Plus|SE|Quadra|Reference|Portable|Color|Toolbox|12)\b|•HC[^\"|,)]*|HyperCard(?:Preview|Common)|Rinaldi|Copyright ©.*Apple Computer|"
                         r"Apple Computer, Inc|© ?\d{4}.*Apple")
DATA_PATH = re.compile(r"HyperCard Stacks\b|examples/apple\S*|hypercard_241_stacks\S*|HyperCard Stacks/\S*|"
                       r"HyperCard%20\S*|devcds/\S*")
MARKER = 'legacy-compat'
IGNORE = 'legacy-terms:ignore'
ALLOW_BEGIN = '<!-- legacy-terms:allow -->'
ALLOW_END = '<!-- /legacy-terms:allow -->'


def tracked_files():
    out = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode().split('\0') if p]


def read_text(path):
    try:
        with open(os.path.join(ROOT, path), 'rb') as f:
            data = f.read()
    except OSError:
        return None
    if b'\0' in data[:8000]:
        return None
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def spans(regex, line):
    return [m.span() for m in regex.finditer(line)]


def inside(pos, ranges):
    return any(a <= pos < b for a, b in ranges)


def code_comment_start(path, line):
    """Column where a comment starts on this code line, or None. Good enough
    for this repository: it ignores comment markers inside strings."""
    if path.endswith('.rs'):
        in_str = False
        i = 0
        while i < len(line) - 1:
            c = line[i]
            if c == '\\' and in_str:
                i += 2
                continue
            if c == '"':
                in_str = not in_str
            elif not in_str and line.startswith('//', i):
                return i
            i += 1
        return None
    if path.endswith(('.py', '.sh', '.yml', '.yaml', '.toml', '.tsv')) or path in ('Cargo.toml',):
        in_s = None
        for i, c in enumerate(line):
            if in_s:
                if c == in_s:
                    in_s = None
            elif c in '\'"':
                in_s = c
            elif c == '#':
                return i
    return None


def string_ranges(line):
    rngs, i, start, q = [], 0, None, None
    while i < len(line):
        c = line[i]
        if q:
            if c == '\\':
                i += 2
                continue
            if c == q:
                rngs.append((start, i + 1))
                q = None
        elif c in '"\'':
            q, start = c, i
        i += 1
    return rngs


def classify(path, line, col, term, text, ctx):
    """(category, disposition) for one match."""
    if FIXTURE.match(path):
        return 'fixture-data', 'retain'
    end = col + len(text)
    if term in ('XCMD', 'XFCN') and ((col > 0 and line[col - 1].isalpha()) or (end < len(line) and line[end].isalpha())):
        return 'third-party-name', 'retain'  # an external's own name: SelectLineXCMD, newTexFcn
    if path in LEGAL:
        return 'legal-notice', 'retain'
    if ctx.get('allow'):
        return 'compat-note', 'retain'
    if MARKER in line:
        return 'compat-literal', 'retain'
    if IGNORE in line:
        return 'false-positive', 'retain'
    for rx, cat in ((FORMAT_IDS, 'format-identifier'), (THIRD_PARTY, 'third-party-name'),
                    (DATA_PATH, 'external-data-path')):
        if inside(col, spans(rx, line)):
            return cat, 'retain'
    if term == 'Mac OS' and inside(col, spans(MODERN, line)):
        return 'modern-platform', 'retain'
    if term == 'Mac' and not re.search(r'classic Mac|old Mac|the Mac\\b(?! app)', line):
        return 'platform-name', 'retain'
    if term == 'macOS' or (term == 'Apple' and inside(col, spans(MODERN, line))):
        return 'modern-platform', 'retain'
    if term == 'Apple' and re.search(r'(?i)sort|pear|\bfig\b|banana|fruit|cherry|\bpie\b', line):
        return 'false-positive', 'retain'
    ext = os.path.splitext(path)[1]
    if ext == '.md' or path in ('README', 'LICENSE') or ext in ('.xml', '.desktop'):
        if ctx.get('fence'):
            return 'script-example', 'retain'
        code = spans(re.compile(r'`[^`]*`'), line)
        link = spans(re.compile(r'\]\([^)]*\)'), line)
        if inside(col, link):
            return 'external-data-path', 'retain'
        if path in GENERATED_LISTINGS and line.startswith('|') and not line.startswith('| Stack') \
                and not line.startswith('| ---'):
            return 'third-party-name', 'retain'
        if inside(col, code):
            return 'code-reference', 'rewrite'
        return 'prose', 'rewrite'
    cstart = code_comment_start(path, line)
    if cstart is not None and col >= cstart:
        return 'comment', 'rewrite'
    if ext == '.py' and ctx.get('docstring'):
        return 'comment', 'rewrite'
    if inside(col, string_ranges(line)):
        return 'string-literal', 'review'
    return 'identifier', 'rewrite'


def scan_text(path, text):
    ctx = {'fence': False, 'allow': False, 'docstring': False}
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if path.endswith('.md'):
            if s == ALLOW_BEGIN:
                ctx['allow'] = True
            elif s == ALLOW_END:
                ctx['allow'] = False
            if s.startswith('```'):
                ctx['fence'] = not ctx['fence']
                if s != '```' and not ctx['fence']:
                    ctx['fence'] = True
        doc_state = ctx['docstring']
        if path.endswith('.py'):
            ctx['docstring'] = doc_state or '"""' in line
        taken = []
        for term, rx in TERM_RES:
            for m in rx.finditer(line):
                a, b = m.span()
                if any(a < tb and ta < b for ta, tb in taken):
                    continue
                taken.append((a, b))
                cat, disp = classify(path, line, a, term, m.group(), ctx)
                yield {'file': path, 'line': n, 'col': a + 1, 'term': term, 'match': m.group(),
                       'category': cat, 'disposition': disp, 'text': line.strip()[:200]}
        if path.endswith('.py'):
            ctx['docstring'] = (not doc_state) if line.count('"""') % 2 else doc_state

def scan_commits():
    fmt = '%H%x1f%an%x1f%ad%x1f%B%x1e'
    out = subprocess.run(['git', 'log', '--all', '--date=short', f'--format={fmt}'], cwd=ROOT,
                         capture_output=True, check=True).stdout.decode('utf-8', 'replace')
    for rec in out.split('\x1e'):
        rec = rec.strip('\n')
        if not rec:
            continue
        sha, author, date, body = rec.split('\x1f', 3)
        for n, line in enumerate(body.splitlines(), 1):
            taken = []
            for term, rx in TERM_RES:
                for m in rx.finditer(line):
                    a, b = m.span()
                    if any(a < tb and ta < b for ta, tb in taken):
                        continue
                    taken.append((a, b))
                    yield {'file': f'commit:{sha[:10]}', 'line': n, 'col': a + 1, 'term': term,
                           'match': m.group(), 'category': 'commit-message', 'disposition': 'retain',
                           'text': f'{date} {author}: {line.strip()[:180]}'}


def scan(commits=False):
    rows = []
    for p in tracked_files():
        if p == 'tools/legacy_terms.py':
            continue
        t = read_text(p)
        if t is not None:
            rows.extend(scan_text(p, t))
    if commits:
        rows.extend(scan_commits())
    return rows


def main(argv):
    mode = argv[1] if len(argv) > 1 else 'audit'
    rows = scan(commits='--commits' in argv)
    if mode == 'check':
        bad = [r for r in rows if r['disposition'] in ('rewrite', 'review')]
        for r in bad:
            print(f"{r['file']}:{r['line']}:{r['col']}: {r['term']} ({r['category']}): {r['text']}")
        print(f'{len(bad)} reference(s) to rewrite or review; {len(rows) - len(bad)} retained.',
              file=sys.stderr)
        return 1 if bad else 0
    keys = ['file', 'line', 'col', 'term', 'match', 'category', 'disposition', 'text']
    if '--csv' in argv:
        with open(argv[argv.index('--csv') + 1], 'w', newline='') as f:
            w = csv.DictWriter(f, keys)
            w.writeheader()
            w.writerows(rows)
    else:
        w = csv.DictWriter(sys.stdout, keys)
        w.writeheader()
        w.writerows(rows)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
