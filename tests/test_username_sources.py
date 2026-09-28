import httpx

from tracex.core.status import SourceStatus
from tracex.core.target import Target, TargetType
from tracex.sources.github import GitHubSource
from tracex.sources.gitlab import GitLabSource
from tracex.sources.reddit import RedditSource

TARGET = Target.parse(TargetType.USERNAME, "lexathegoat")


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_github_found():
    def handler(request):
        return httpx.Response(200, json={"html_url": "https://github.com/lexathegoat", "public_repos": 5})
    r = await GitHubSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.FOUND
    assert r.entities[0].value == "lexathegoat"


async def test_github_not_found():
    def handler(request):
        return httpx.Response(404)
    r = await GitHubSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.NOT_FOUND


async def test_github_rate_limited():
    def handler(request):
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "0"})
    r = await GitHubSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.RATE_LIMITED


async def test_gitlab_found():
    def handler(request):
        return httpx.Response(200, json=[{"username": "lexathegoat", "name": "Lexa", "web_url": "x"}])
    r = await GitLabSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.FOUND


async def test_gitlab_ignores_partial_matches():
    def handler(request):
        return httpx.Response(200, json=[{"username": "lexathegoat2", "name": "Other"}])
    r = await GitLabSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.NOT_FOUND


async def test_reddit_found():
    def handler(request):
        return httpx.Response(200, json={"data": {"total_karma": 100, "is_suspended": False}})
    r = await RedditSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.FOUND


async def test_reddit_suspended():
    def handler(request):
        return httpx.Response(200, json={"data": {"is_suspended": True}})
    r = await RedditSource(_client(handler)).run(TARGET)
    assert "suspended" in r.findings[0].title.lower()


async def test_reddit_not_found():
    def handler(request):
        return httpx.Response(404)
    r = await RedditSource(_client(handler)).run(TARGET)
    assert r.status is SourceStatus.NOT_FOUND