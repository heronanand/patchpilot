"""Post the report on the merge request that triggered the pipeline."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request


class GitLabConfigError(RuntimeError):
    pass


def mr_context(env: dict[str, str] | None = None) -> tuple[str, str, str, str]:
    env = dict(os.environ if env is None else env)
    needed = ["CI_API_V4_URL", "CI_PROJECT_ID", "CI_MERGE_REQUEST_IID", "PATCHPILOT_GITLAB_TOKEN"]
    missing = [k for k in needed if not env.get(k)]
    if missing:
        raise GitLabConfigError(
            "Cannot post to the merge request; missing " + ", ".join(missing)
            + ". Run in a merge-request pipeline and add a project access token as PATCHPILOT_GITLAB_TOKEN."
        )
    return tuple(env[k] for k in needed)  # type: ignore[return-value]


def post_mr_note(body: str, env: dict[str, str] | None = None, opener=urllib.request.urlopen) -> int:
    api, project, mr_iid, token = mr_context(env)
    url = f"{api}/projects/{urllib.parse.quote(project, safe='')}/merge_requests/{mr_iid}/notes"
    request = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode("utf-8"),
        headers={"PRIVATE-TOKEN": token, "Content-Type": "application/json"},
        method="POST",
    )
    with opener(request, timeout=30) as response:
        return response.status
