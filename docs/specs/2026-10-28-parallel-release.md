# The release builds its three artifacts at once

`release-apple.yml` builds the XCFramework, publishes the release, and only
then dispatches the AAR and desktop-binary builds onto the tag. Those two
builds do not depend on the framework, so the release's wall time is the
sum of the three rather than the slowest one. This change starts all three
at once and publishes when all three have attached.

Written 2026-10-28 against `mobile` at v0.9.0, on top of the CI changes in
#123 to #125 (cancel closed PRs' runs; release builds off the PR path with
caches that reach a release; the lint gate). The timing that motivates it
is the v0.8.4 release the same day: 10 minutes queued for a macOS runner,
24 minutes of cold framework build, then 15 minutes of fan-out, plus a
re-run when a fan-out macOS job was cancelled without a runner.

## Problem

The release pipeline is serial by construction, not by need:

1. `release-apple.yml` (`.github/workflows/release-apple.yml:35-124`) runs
   one job: validate the version, build the XCFramework (10 to 25 min),
   zip and checksum it, commit `Package.swift`, push, create a draft
   release carrying the zip, publish it (which creates the tag at the
   manifest commit), then dispatch `mobile.yml` and `build.yml` on the tag.
2. `build.yml`'s `release` job (`:296-324`) and `mobile.yml`'s
   (`:388-454`) run only on `refs/tags/*`, download their build artifacts
   and append them to the release by tag name. Another 15 minutes, after
   the publish.

Nothing the AAR or the desktop binaries contain depends on the framework
or on `Package.swift`; they are built from the same source tree either
way. The only thing the serial order buys is that the tag exists when
they attach, and a draft release can take assets before it has a tag.

## Scope

`release-apple.yml`, and the `release` jobs plus `workflow_dispatch` inputs
of `build.yml` and `mobile.yml`. The draft-then-publish recovery stays:
nothing irreversible happens before every asset is attached, and a
re-run of a failed release finds the draft and finishes it. Tag pushes by
hand keep failing the manifest check in `mobile.yml`, as today. No change
to what the artifacts contain or how they are built.

## What the references do

The reference is this repository's own release flow, whose invariants the
change keeps (`release-apple.yml`, header comment):

- The manifest must name the checksum of the zip for the tag it is on,
  so the zip is built and committed before the tag exists, and publishing
  the draft is what creates the tag at the manifest commit.
- A tag created by the API with the workflow's token fires no `on: push`
  workflow, so the fan-out builds are dispatched explicitly.
- `mobile.yml`'s release job refuses a tag whose `Package.swift` does not
  name it, which is how a hand-pushed tag is caught.

GitHub's side, verified with `gh` 2.103: a draft release is created with
`--draft --target <sha>` and no tag; `gh release upload <tag> <file>`
resolves a draft by its tag name; `gh release edit <tag> --target <sha>`
moves a draft's target before publish; `gh run list --created
'>=<timestamp>' --event workflow_dispatch` finds the runs a dispatch
started.

## What changes

1. **The draft is created first.** After the version check, the release
   job creates the draft `v$VERSION` with `--target $(git rev-parse HEAD)`
   (the bump merge commit on `mobile`), no assets, generated notes. The
   recovery check at the top moves with it: a draft that already carries
   `Shoes.xcframework.zip` means a previous run got as far as the manifest
   commit, and the run goes straight to waiting and publishing.

2. **The fan-out builds start at once, on `mobile`, uploading to the
   draft.** The release job dispatches `build.yml` and `mobile.yml` with a
   new `workflow_dispatch` input, `release_tag` (default empty), on the
   `mobile` ref, right after the draft exists. Both workflows' `release`
   jobs run when `startsWith(github.ref, 'refs/tags/') || inputs.release_tag
   != ''`, and upload with `gh release upload "$TAG" <files> --clobber`
   where `TAG` is `inputs.release_tag` on dispatch and `github.ref_name` on
   a tag push; `softprops/action-gh-release` is dropped from these two
   jobs, since the release already exists either way and `gh` resolves a
   draft by tag. `mobile.yml`'s manifest check runs only on the tag-push
   path: on dispatch the manifest is being written by the caller at that
   moment, and the caller is the one producer of the framework. The
   binaries are built from the bump commit, one commit before the tag's
   manifest commit; the only difference between the two trees is
   `Package.swift`, which no binary reads. The release notes say so.

3. **The framework builds in parallel and the manifest lands as before.**
   The release job builds the XCFramework, zips, checksums, commits
   `Package.swift`, pushes `mobile`, uploads the zip to the draft with
   `gh release upload`, and retargets the draft to the manifest commit
   with `gh release edit --target`.

4. **Publish waits for the fan-out.** The release job finds the two
   dispatched runs (`gh run list --workflow <file> --branch mobile --event
   workflow_dispatch --created ">=$STARTED"`, newest first) and `gh run
   watch`es each to completion, failing the release if either failed. Then
   it checks the draft carries all 14 expected assets by name, and only
   then publishes, which creates the tag. The post-publish dispatch onto
   the tag is removed.

5. **The tag-push path stays.** A `v*` tag pushed by hand still runs
   `build.yml` and `mobile.yml` on the tag; `build.yml`'s release job
   creates or appends to the release as today (via `gh release create`
   if none exists, then upload), and `mobile.yml`'s manifest check still
   refuses a tag the manifest does not name.

6. **A dry run.** A `dry_run` input on `release-apple.yml` (default
   false) runs the whole flow against a draft named `v$VERSION-dryrun`,
   skips the "tag already exists" and "Cargo.toml must match" refusals,
   dispatches the fan-out with that tag, uploads the framework, and at the
   end deletes the draft instead of publishing, with no commit to
   `Package.swift` and no push. It is how this change is tested before a
   real release depends on it, and how a change to the release flow is
   tested afterwards.

7. **Documentation.** The header comment of `release-apple.yml` describes
   the new order. `docs/MACOS.md` or wherever the release procedure is
   written, if anywhere, says the same. `CHANGELOG.md` under Unreleased.

## Error handling

- A fan-out run that fails or is cancelled: the release job fails before
  publish, the draft stays with whatever attached, and a re-run finds the
  draft and the zip and goes to the wait step again, re-dispatching only
  the builds whose assets are missing (checked by asset name).
- A macOS fan-out job cancelled without a runner, as on 2026-10-28: the
  same as a failure; the re-run re-dispatches `build.yml`, which rebuilds
  all seven targets (the seven Linux and Windows archives are re-uploaded
  with `--clobber`).
- The manifest commit push rejected (someone pushed to `mobile` during the
  release): the job fails before publish, no tag, the draft deleted by the
  operator or left for the re-run, which rebuilds on the new head.
- `dry_run` leaves nothing behind: the draft is deleted in a step that
  runs `if: always()` once the dry run began.

## Testing

- The dry run, dispatched on the PR branch with `version` set to the
  current Cargo.toml version and `dry_run: true`: both fan-out runs start
  within a minute of the release run, the draft collects 14 assets, and
  the draft is gone at the end. This is the whole flow minus the
  irreversible step, and it is run before the PR merges.
- `mobile.yml`'s manifest check on a hand-pushed tag is unchanged and
  keeps its existing verification path.
- The first real release after merge is watched end to end.

## Out of scope

- Speeding up the XCFramework build itself (its cache is #124's job).
- The 10-minute macOS runner queue, which is GitHub's.
- Retrying a cancelled fan-out job automatically; a re-run of the release
  workflow does that with one click.
