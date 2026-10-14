import json

import pytest

from patchpilot.gitlab import GitLabConfigError, post_mr_note

ENV = {
    "CI_API_V4_URL": "https://gitlab.example.com/api/v4",
    "CI_PROJECT_ID": "42",
    "CI_MERGE_REQUEST_IID": "7",
    "PATCHPILOT_GITLAB_TOKEN": "glpat-test",
}


class _Response:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_posts_note_to_merge_request():
    seen = {}

    def opener(request, timeout):
        seen["url"], seen["headers"], seen["body"] = request.full_url, dict(request.header_items()), json.loads(request.data)
        return _Response()

    assert post_mr_note("hello", env=ENV, opener=opener) == 201
    assert seen["url"] == "https://gitlab.example.com/api/v4/projects/42/merge_requests/7/notes"
    assert seen["headers"]["Private-token"] == "glpat-test"
    assert seen["body"] == {"body": "hello"}


def test_missing_context_explains_what_to_set():
    with pytest.raises(GitLabConfigError, match="PATCHPILOT_GITLAB_TOKEN"):
        post_mr_note("x", env={k: v for k, v in ENV.items() if k != "PATCHPILOT_GITLAB_TOKEN"})
