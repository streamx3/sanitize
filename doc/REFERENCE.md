# sanitize — flags and configuration reference

> **Status: review draft.** This is the single place where every flag and every config key is
> defined, with its category and its authority. Written to be reviewed first, implemented second,
> and shipped as the user-facing reference third. Section 7 is the implementation delta against
> the code as it stands; section 8 is what still needs a decision.
>
> Per-entry status: **shipped** (in `src/` today) · **designed** (in DESIGN.md, not built) ·
> **new** (decided 2026-09-21, not yet written down anywhere else).

---

## 0. The governing rule

Every setting in this tool falls into exactly one of three categories, and the category decides
who is allowed to set it.

| Category | Question it answers | May be set by |
|---|---|---|
| **Scope** | *Which bytes get destroyed?* | **command line only** |
| **Out-of-tree residue** | *Which well-known OS artefacts outside the target go too?* | config or CLI, **always disclosed** |
| **Thoroughness** | *How completely are the already-chosen bytes destroyed?* | config or command line |
| **Ceremony** | *How much do we ask, and how much do we print?* | config or command line |

The test for deciding which bucket a new setting belongs in:

> **Does this change *which* bytes are destroyed, or only how thoroughly the already-chosen bytes
> are destroyed?**

If it changes the set, it is scope.

### 0.1 Why scope is command-line-only

**The set of bytes to be destroyed must be determined entirely by the command line.**

Not because the operator can't be trusted — §16.4 of DESIGN.md settles that: they can. Because a
config file is *invisible at the call site*. When you type `sanitize ~/notes`, the destruction set
should be readable from that line and the filesystem, and from nothing else. A setting that can
silently redirect *what dies* must be visible in the same place the target is named.

This is also what makes the scope flags qualitatively different from the rest: **their blast radius
is determined by filesystem contents rather than by the flag.** `--follow-symlinks` does not mean
"try harder", it means "destroy whatever these links happen to point at" — and what they point at
may have been chosen by someone else. Contrast `--no-scrub-times`, whose effect is fully described
by the flag itself, on exactly the files you named.

### 0.2 What this buys

Once scope is off the table, a hijacked `/etc/sanitize/default.conf` stops being a
privilege-escalation vector and becomes an annoyance: the worst an attacker who owns that file can
do is skip your confirmation prompt or turn off residue scrubbing. They cannot turn
`sanitize ~/notes` into `sanitize -F /`, because no config key exists that could express it.

That is the whole answer to "how exactly should this work". Not a blocklist of dangerous keys —
those rot, and the next flag gets forgotten. A structural property: **there is no config key for
scope, so there is nothing to blocklist.**

### 0.3 The residue carve-out, stated honestly

The first draft of this document classified `--scrub-sidecars` and `--scrub-volume` as
thoroughness. That was wrong by this document's own test: `sanitize /Volumes/STICK/folder` with
volume scrubbing on destroys `/Volumes/STICK/.fseventsd`, which is not under the named path. It
changes *which* bytes die, so by §0 it is scope, and scope is command-line-only — which would
contradict the §16.4 decision that these default to on.

The rule needs a second clause rather than an exception:

> Scope is a setting whose additional byte set is **not enumerable from the command line**.

Symlink following and mount crossing fail that test: what they destroy depends on where links
point and what happens to be mounted, neither knowable from the invocation. Residue scrubbing
passes it: the set is a fixed, documented list of OS-generated paths at a computable location.
You can read `SHORTCOMINGS.md` §1.1 and know exactly what it will touch.

So residue scrubbing is its own category — outside the tree, but bounded — and it is config-legal
on that basis, not by pretending it stays inside the target. Two obligations come with the
carve-out:

1. **It is always disclosed**, per §5.4, on every run that touches anything outside the named
   paths. A bounded set is only knowable if we say which members we hit.
2. **`$RECYCLE.BIN` and `.Trashes` are the weak members.** Their *paths* are enumerable, but their
   *contents* are arbitrary user files of unbounded size, possibly written by a different person on
   a different machine. They stay in by the §16.4 threat model — a trashed file is a recoverable
   copy of exactly what you asked to destroy — but they are the one place where "bounded" means
   bounded in location only. Reported as a distinct class.

### 0.4 The corollary about `-F`

`-F` is dangerous today not because it is aggressive but because it is a **bundle that mixes
categories**: it permits dangerous paths *(scope)*, follows symlinks *(scope)*, crosses mount
points *(scope)*, and implies `-f` chmod *(thoroughness)*.

The fix is not to ban `-F` from config. It is to **unbundle it**, after which the config question
answers itself — the scope members have no config keys, the thoroughness member does. `-F` survives
as a command-line-only alias for its scope members, which keeps muscle memory and makes the bundle
auditable rather than magic.

---

## 1. Scope — command line only

None of these may ever appear in a config file. Each can destroy something the user did not name.

| Flag | Default | Effect | Status |
|---|---|---|---|
| `--no-preserve-root` | off | Permit `/` itself as a target. Long-only, no short form, exactly as `rm`. | **new** |
| `--follow-symlinks` | off | Destroy symlink *targets*, not just the links. Cycle-safe via a visited `(st_dev, st_ino)` set. | **new** (today: reachable only via `-F`) |
| `--no-one-file-system` | off | Descend across mount points, partitions and drives. | **shipped** |
| `--hard-links=shred` | `skip` | Destroy content reachable under another name outside the tree. | **shipped** |
| `-F`, `--force-everything` | off | Alias for all four above, plus `-f` and `--yes`. Nothing else. | **shipped** (semantics narrow slightly) |

### 1.1 Why each one is scope, not thoroughness

- **`--no-preserve-root`** — the one acknowledged special case in this taxonomy. It does not add
  bytes you did not name: if you typed `/`, you named `/`. By the letter of §0 it is therefore
  ceremony, not scope. It is a command-line-only flag anyway, on consequence rather than category:
  `rm -rf $FOO/` with `$FOO` unset is the classic disaster, `/` is where it lands, and that one
  case is worth a gate that a config file cannot open. Every *other* dangerous path is handled by
  warn-and-wait instead — see §3.1. There is no `--allow-dangerous-path`, and there should not be:
  the guard list is exact-match and already bypassable by a shell glob, so it is a typo guard, not
  a security boundary, and a typo guard is exactly what a confirmation prompt is for.
- **`--follow-symlinks`** — the escalation that motivated this whole section. A symlink planted
  inside a tree you are about to sanitize redirects destruction anywhere the link points. Note the
  precondition is *write access to a directory you were going to destroy anyway* — far weaker than
  write access to `/etc`. This one must be deliberate per run.
- **`--no-one-file-system`** — the destruction set becomes "whatever happened to be mounted",
  which is not knowable from the command line. A backup drive mounted under the tree is destroyed
  with no mention of it anywhere in the invocation.
- **`--hard-links=shred`** — the *bytes* are inside the tree, but the observable effect is that a
  path outside the tree loses its content. The user cannot predict that from their command line,
  which is the test. (Weakest of the five — see §8.)

### 1.2 `-F` after unbundling

`-F` is defined as exactly:

```
--no-preserve-root --follow-symlinks --no-one-file-system --hard-links=shred -f --yes
```

No other behaviour is attached to it. It is command-line-only because four of its six members are.
The consequence recorded in DESIGN.md §16.3 is unchanged: `sudo sanitize -F /` destroys every
mounted volume reachable from the tree. That remains the documented purpose of the flag.

---

## 2. Thoroughness — config or command line

These change how completely the chosen bytes die. None can add a path to the destruction set.

| Flag | Default | Config key | Status |
|---|---|---|---|
| `-n N`, `--iterations N` | `1` | `iterations` | **shipped** |
| `-f`, `--force` | off | `force_perms` | **shipped** |
| `-x`, `--exact` | off | `exact` | **shipped** |
| `-z`, `--zero` | off | `zero` | **shipped** |
| `-k`, `--keep` | off | `keep` | **shipped** |
| `--remove=unlink\|wipe\|wipesync` | `wipesync` | `remove` | **shipped** |
| `--head SIZE` / `--tail SIZE` | whole file | `head` / `tail` | **shipped** |
| `-s N`, `--size N` | — | — | **shipped** (alias for `--head`) |
| `--random-source FILE` | CSPRNG | `random_source` | **shipped** |
| `--no-recursive` | recursive | `recursive` | **shipped** |
| `--no-scrub-times` | scrubbing on | `scrub_times` | **shipped** |
| `--no-truncate` | truncating on | `truncate_before_unlink` | **shipped** |
| `--scrub-dirents` | off | `scrub_dirents` | **designed** (DESIGN §5.4) |
| `--verify` | off | `verify` | **designed** |
| `--range A:B` | — | — | **designed** (DESIGN §4.2) |
| `-j N`, `--jobs N` | `1` | `jobs` | **designed** |

`--no-recursive` is thoroughness rather than scope: it can only ever *shrink* the set. Settings
that shrink the set are always safe to put in config; only expansion is restricted.

---

## 2a. Out-of-tree residue — config or command line, always disclosed

Bounded and enumerable (`SHORTCOMINGS.md` §1.1), but outside the named target. See §0.3.

| Flag | Default | Config key | Status |
|---|---|---|---|
| `--no-scrub-sidecars` | scrubbing on | `scrub_sidecars` | **shipped** |
| `--no-scrub-volume` | scrubbing on | `scrub_volume` | **new** |

Even the AppleDouble sidecar escapes the named path when the target is a single *file*:
`sanitize ~/notes/a.txt` must reach `~/notes/._a.txt`, a sibling rather than a child. All three
residue classes share that property, which is why they share a category.

---

## 3. Ceremony and output — config or command line

| Flag | Default | Config key | Status |
|---|---|---|---|
| `-N`, `--dry-run` | off | `dry_run` | **shipped** |
| `-v`, `--verbose` | off | `verbose` | **shipped** |
| `--json` | off | `json` | **shipped** |
| `--yes` | off | `assume_yes` | **new** |
| `-I` | auto above ~50 files | `interactive_threshold` | **designed** (DESIGN §7.4) |
| `--explain` | off | `explain` | **designed** (TODO P0.1 — *advertised in output today but not implemented*) |
| `--config PATH` | — | — | **new** |
| `--no-config` | off | — | **new** |

### 3.1 `--yes` and warn-and-wait

Warn-and-wait is new; nothing in `src/` prompts today. The intended model:

- `/` refuses outright without `--no-preserve-root`. A prompt is not a substitute for that flag.
- Every **other** dangerous path (`/usr`, `/etc`, `$HOME`, `/Volumes`, … — the `guards.rs` list)
  warns and waits, naming the path. This replaces the `--allow-dangerous-path` flag of the first
  draft: the guard is exact-match and a shell glob walks straight past it, so it was never a
  boundary — it is a "did you mean this?", and that is a prompt's job.
- A run above the `-I` threshold also warns and waits.
- `--yes` skips the wait. `assume_yes = true` in config skips it for every run.
- **If stdin is not a TTY and `--yes` was not given, refuse (exit 3).** Never treat a
  non-interactive stream as consent. A script that was safe because it stopped at a prompt must not
  become destructive because nobody was there to answer.

**This is the setting that solves the leaving-a-building case.** It is pure ceremony — it changes
nothing about which bytes die — so it is config-legal with no caveats, and needs none of the scope
flags to work. The thing you actually wanted turns out to be on the safe side of the line; the
thing that is dangerous (`force_everything = true`) turns out to be something you never needed.

---

## 4. shred compatibility

DESIGN.md §4.1 commits to accepting all of `shred`'s options with `shred`'s meanings, except `-u`
(our default). Two deliberate divergences: `-n` defaults to 1, and deletion is on.

| shred | sanitize | Note |
|---|---|---|
| `-f` | `-f` | **Keep.** See below. |
| `-n`, `-s`, `-v`, `-x`, `-z`, `--random-source`, `--remove` | identical | |
| `-u` | accepted, hidden | removal is already the default |
| `-r`/`-R` | accepted, hidden | recursion is already the default |

### 4.1 Why `-f` stays distinct from `-F`

Three reasons, the third being the one that matters under this document's model:

1. **Compatibility is an explicit design goal.** `shred -fuz path` should work. Dropping `-f`
   forfeits that for no gain.
2. **The magnitudes are not comparable.** `-f` is `chmod u+w` on a file you already own and already
   named. `-F` crosses mount points and follows symlinks. Folding the first into the second means
   anyone who just wants to overwrite a read-only file must also accept symlink following — forcing
   over-privilege on the common case is bad flag hygiene.
3. **They are in different categories.** `-f` is thoroughness: config-legal, cannot expand the set.
   `-F` is scope: command-line-only. They are not "small force" and "big force" on one axis — they
   are on different axes, and this document's whole structure depends on not conflating them.

`-F` continues to imply `-f`, which is correct: a bundle may include members from any category.

---

## 5. Configuration file

### 5.1 Precedence

```
hardcoded defaults  <  /etc/sanitize/default.conf  <  command line
```

Later wins. The command line always wins. `--config PATH` replaces the `/etc` layer;
`--no-config` skips it entirely.

### 5.2 Format

Flat `key = value`, one per line, `#` to end of line for comments. Booleans are `true`/`false`.
Unknown keys are an error naming the key and line number, not a silent ignore — a typo'd
`scrub_volume` must not read as "off". Parsed in-tree: the crate denies `unwrap`, `expect` and
`panic`, and a config parser does not justify a new supply-chain edge.

```conf
# /etc/sanitize/default.conf
assume_yes  = true      # the leaving-a-building case
iterations  = 1
scrub_volume = true
```

### 5.3 What a config file may never contain

Every key in §1. There are no such keys — this is structural, not a blocklist. A config containing
`force_everything`, `follow_symlinks`, `no_one_file_system`, `no_preserve_root`,
`allow_dangerous_path`, or `hard_links = shred` is a **hard error** naming the key, not a warning
and not an ignore. Failing loudly is the only way the operator learns their config is not doing
what they think.

### 5.4 Disclosure

Every run that destroys anything prints the layers in effect and the provenance of every
non-default setting:

```
sanitize: config: /etc/sanitize/default.conf (assume_yes, scrub_volume)
sanitize: config: command line (--no-scrub-times, --follow-symlinks)
```

A destructive tool that can be silently reconfigured is a destructive tool that can silently lie
about what it did — the same defect class as printing "securely erased".

### 5.5 Trust — decided: `/etc/sanitize/` is trusted, no checks

An earlier draft recommended refusing a group- or world-writable config. **Dropped**, for a reason
that defeats it outright:

> Anyone who can write `/etc/sanitize/default.conf` can replace the `sanitize` binary. A
> permission check on the config protects nothing an attacker with that access has not already
> bypassed.

The only scenario it would catch is `/etc/sanitize/` left world-writable by a broken install — a
system misconfiguration, not this tool's to police. And by §0.2 the payload is now bounded anyway:
a hijacked config cannot reach a scope key, so the worst it achieves is skipping a prompt or
leaving residue unscrubbed.

So: the config is read and trusted. What stays is §5.4 **disclosure** — not as a security control,
but because an operator who forgot they set `scrub_volume = false` needs to see it in the output of
the run that relied on it.

---

## 6. Exit codes

| Code | Meaning | Status |
|---|---|---|
| `0` | everything destroyed, no residue left unhandled | **shipped** |
| `1` | something was skipped, failed, or left residue | **shipped** (residue part **new**, DESIGN §16.7) |
| `2` | usage error | **shipped** |
| `3` | refused for safety, nothing touched | **shipped** |

---

## 7. Implementation delta against `src/` as it stands

1. **`--follow-symlinks` does not exist.** `cli.rs:203` sets `follow_symlinks: cli.force_everything`
   — the behaviour is reachable *only* through `-F`. Needs its own flag before `-F` can be defined
   as an alias.
2. **`guards.rs::check()` takes `force_everything: bool`.** It needs a scope-permission set
   instead, so `--no-preserve-root` can be honoured independently and the rest of the list can
   fall through to warn-and-wait. Today `-F` is the only bypass.
3. **DESIGN.md §7.4 contradicts §16.3.** §7.4 names `--allow-dangerous-root`; §16.3 says `-F` is
   required and sufficient; the code implements §16.3. §16 supersedes, so §7.4 should be corrected
   to reference the §1 flags of this document.
4. **No config loading exists.** Nothing in `src/` reads a file; `Config::from_cli` is the only
   constructor. Needs a `Config::layered(defaults, file, cli)` with provenance tracking for §5.4.
5. **No prompt exists.** `-I` and warn-and-wait are designed but unbuilt; `-F` is currently
   documented as "no prompt, no countdown", which §3.1 narrows to "no prompt once the target is
   permitted".
6. **`--explain` is advertised but absent** (`report.rs:262`). Unchanged from TODO P0.1.

---

## 8. Open questions

Resolved since the first draft, recorded so the reasoning is not relitigated:

| Was open | Resolved |
|---|---|
| `--hard-links=shred` as scope | **Moot on the priority filesystems** — FAT32/exFAT have no hard links, so the setting is a no-op there. Stays in §1 as scope for ext4/NTFS/APFS; revisit when those become a target, not before. |
| Config trust | **Trust it.** §5.5. |
| Per-user `~/.config` layer | **No.** Two layers plus the command line; no third. |
| `--allow-dangerous-path` granularity | **Flag removed entirely.** Warn-and-wait covers the list; `/` keeps its own gate. §1.1, §3.1. |
| `-f` vs `-F` | **Both stay**, in different categories. §4.1. |

Still open:

1. **Symlink policy, deferred by decision.** FAT32/exFAT have no symlinks, so the question does not
   arise on the priority filesystems. `--follow-symlinks` stays specified and unbuilt until a
   stable FAT-first release exists; the right semantics are then argued on their own merits rather
   than inherited from `-F`.
2. **What warn-and-wait actually looks like.** A `y/N` read, a typed confirmation, or a countdown.
   The non-TTY rule in §3.1 matters more than the shape.
