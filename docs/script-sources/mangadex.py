# @id        mangadex-py
# @name      MangaDex (Python script)
# @lang      en
# @base      https://mangadex.org
# @supports  latest popular
#
# An example script source: copy it to SOURCES_DIR/scripts/ and reload sources. Standard library only.
# Usage: python3 mangadex.py search "one piece" 1 | series <id> | chapters <id> | pages <id> | latest 1 | popular 1
import json
import sys
import urllib.parse
import urllib.request

API = "https://api.mangadex.org"
LANG = "en"
PER_PAGE = 20


def get(path, **params):
    url = f"{API}{path}?{urllib.parse.urlencode(params, doseq=True)}"
    req = urllib.request.Request(url, headers={"User-Agent": "uchiyomi-script-source"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def pick(d):
    """The English text of a localised map, else any."""
    return (d or {}).get(LANG) or next(iter((d or {}).values()), None)


def series(m):
    a = m["attributes"]
    rel = {r["type"]: r for r in m.get("relationships", [])}
    cover = rel.get("cover_art", {}).get("attributes", {}).get("fileName")
    return {
        "id": m["id"],
        "title": pick(a.get("title")),
        "summary": pick(a.get("description")),
        "status": a.get("status"),
        "genres": [pick(t["attributes"]["name"]) for t in a.get("tags", [])],
        "author": rel.get("author", {}).get("attributes", {}).get("name"),
        "cover": f"https://uploads.mangadex.org/covers/{m['id']}/{cover}.256.jpg" if cover else None,
        "url": f"https://mangadex.org/title/{m['id']}",
        "updatedAt": a.get("updatedAt"),
    }


def listing(page, **params):
    r = get("/manga", limit=PER_PAGE, offset=(int(page) - 1) * PER_PAGE,
            **{"includes[]": ["cover_art"], "availableTranslatedLanguage[]": [LANG]}, **params)
    return [series(m) for m in r["data"]]


def search(query, page="1"):
    return listing(page, title=query)


def latest(page="1"):
    return listing(page, **{"order[latestUploadedChapter]": "desc"})


def popular(page="1"):
    return listing(page, **{"order[followedCount]": "desc"})


def get_series(sid):
    return series(get(f"/manga/{sid}", **{"includes[]": ["cover_art", "author"]})["data"])


def chapters(sid):
    out, offset = [], 0
    while True:
        r = get(f"/manga/{sid}/feed", limit=500, offset=offset,
                **{"translatedLanguage[]": [LANG], "order[chapter]": "asc", "includes[]": ["scanlation_group"]})
        for c in r["data"]:
            a = c["attributes"]
            if a.get("externalUrl"):
                continue  # hosted elsewhere: no pages here
            groups = [g["attributes"]["name"] for g in c["relationships"] if g["type"] == "scanlation_group" and g.get("attributes")]
            out.append({
                "id": c["id"],
                "number": a.get("chapter"),
                "title": a.get("title"),
                "lang": a.get("translatedLanguage"),
                "publishedAt": a.get("publishAt"),
                "scanlator": " & ".join(groups) or None,
            })
        offset += len(r["data"])
        if not r["data"] or offset >= r["total"]:
            return out


def pages(cid):
    r = get(f"/at-home/server/{cid}")
    base, ch = r["baseUrl"], r["chapter"]
    return [f"{base}/data/{ch['hash']}/{f}" for f in ch["data"]]


COMMANDS = {"search": search, "series": get_series, "chapters": chapters, "pages": pages,
            "latest": latest, "popular": popular}

if __name__ == "__main__":
    cmd, *args = sys.argv[1:] or ["?"]
    if cmd not in COMMANDS:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)
    try:
        print(json.dumps(COMMANDS[cmd](*args)))
    except Exception as e:  # the last stderr line is the error Uchiyomi shows
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
