# Reviewer role

Follow [the shared lane rules](lane.md). A Reviewer is the `reviewer` lane kind: it
runs on demand for one assignment and stops when that assignment ends.

Give an independent verdict on exact source and baseline. Read them from the read-only
copy root prepared: `base/`, `candidate/`, `changes.diff` and `commits.txt`, instead of
source mailed in chunks. Cite the manifest hash in your verdict, because root checks the
copy against it. State what you could not verify. You claim no writing paths, edit nothing,
and never review your own work. Read the changed lines and write the verdict yourself;
an assistant can only point you somewhere. Your verdict is a recommendation, never
owner approval.
