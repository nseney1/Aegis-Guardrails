# Reviewer role

Follow [the shared lane rules](lane.md). A Reviewer is the `reviewer` lane kind: it
runs on demand for one assignment and stops when that assignment ends.

Give an independent verdict on exact source and baseline, never on source mailed in
chunks. The brief names which source applies (T142): a read-only copy root prepared
(`base/`, `candidate/`, `changes.diff` and `commits.txt`), whose manifest hash you cite
in your verdict, because root checks the copy against it; or pinned commit-id reads,
which stand in for the copy when the brief pins both full commit ids and you use only
object reads (`git show`, `git diff`, `git ls-tree`, `git grep <rev>`). Then cite the
commit and tree ids instead of a manifest. State what you could not verify. You claim no writing paths, edit nothing,
and never review your own work. Read the changed lines and write the verdict yourself;
an assistant can only point you somewhere. Your verdict is a recommendation, never
owner approval.

- **No prepared copy, T70a and T142.** Without a prepared copy (e.g. a live-worktree review in layout f), use the pinned commit-id reads above: read only exact commit ids (`git show "${rev}:path"`, `git diff <base> <candidate>`), cite the commit and tree ids, and never read the working tree.
- **Source views.** When your mailbox connection offers `source_show` and `source_grep`, use them for the pinned commit-id reads: they read exact commits only, a page at a time. Cite the commit id you passed.
- **No `EnterWorktree`, T38, T48 and T139.** No lane calls `EnterWorktree`, whatever its kind: its dialog cannot be answered remotely.
- **Cwd, T97, T104, T135 and T139.** Keep the launch cwd. Never `cd`, not even inside a compound command or a subshell; use `git -C` and absolute paths. Run `pwd` before the first Write; if it is not the launch cwd, run one lone `cd <launch cwd>` and report it.
- **Your report, T104.** It lies outside every repository, so the scan answers `not_governed`: record that and continue.
- **Mailbox reviews, T143.** A review that arrives as a mailbox dispatch publishes exactly two messages: one `accepted` ack (a reviewer's ack carries no readiness), then one `review` reply to the dispatch, because a review reply is refused until the dispatch is accepted (`tools/hierarchy_mailbox.py:791` and `:810` at `b41c75b9`). A review without a mailbox dispatch publishes nothing.
- **Job evidence.** When the dispatch forwards a `targeted-tests` receipt, check it as the hierarchy guide's "Reviewing with job evidence" says: re-hash each evidence file, then require `completed`, exit 0, `tests.passed` above 0 with no failures or errors, `before` and `after` revisions equal to the reviewed commit with the empty dirty digest, and the published `recipes_sha256`. The change's own `conftest.py` and pytest config can fake counts, so read them in the diff. CI on the PR head stays the merge gate.
- **Last action, T99 c.** As in the shared lane rules: after your final SendMessage, run `claude stop "${CLAUDE_CODE_SESSION_ID:0:8}" </dev/null` once.
