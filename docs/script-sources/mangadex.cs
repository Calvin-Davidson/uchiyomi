// @id        mangadex-cs
// @name      MangaDex (C# script)
// @lang      en
// @base      https://mangadex.org
// @supports  latest popular
//
// An example script source: copy it to SOURCES_DIR/scripts/ and reload sources. A .NET 10 file-based app, no project.
// Usage: dotnet run mangadex.cs -- search "one piece" 1 | series <id> | chapters <id> | pages <id> | latest 1 | popular 1
using System.Text.Json.Nodes;

const string Api = "https://api.mangadex.org";
const string Lang = "en";
const int PerPage = 20;

var http = new HttpClient();
http.DefaultRequestHeaders.UserAgent.ParseAdd("uchiyomi-script-source");

if (args.Length == 0)
{
    Console.Error.WriteLine("no command");
    return 2;
}

try
{
    JsonNode? result = args[0] switch
    {
        "search" => await Listing(Arg(2, "1"), ("title", Arg(1))),
        "latest" => await Listing(Arg(1, "1"), ("order[latestUploadedChapter]", "desc")),
        "popular" => await Listing(Arg(1, "1"), ("order[followedCount]", "desc")),
        "series" => Series((await Get($"/manga/{Arg(1)}", ("includes[]", "cover_art"), ("includes[]", "author")))["data"]!),
        "chapters" => await Chapters(Arg(1)),
        "pages" => await Pages(Arg(1)),
        _ => throw new ArgumentException($"unknown command {args[0]}"),
    };
    Console.WriteLine(result?.ToJsonString() ?? "null");
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine(e.Message); // the last stderr line is the error Uchiyomi shows
    return 1;
}

string Arg(int i, string fallback = "") => args.Length > i ? args[i] : fallback;

async Task<JsonNode> Get(string path, params (string Key, string Value)[] query)
{
    var qs = string.Join("&", query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
    using var r = await http.GetAsync($"{Api}{path}?{qs}");
    if (!r.IsSuccessStatusCode) throw new Exception($"MangaDex answered {(int)r.StatusCode} for {path}");
    return JsonNode.Parse(await r.Content.ReadAsStringAsync())!;
}

// The English text of a localised map, else any.
string? Pick(JsonNode? d) => d is JsonObject o ? (string?)(o[Lang] ?? o.FirstOrDefault().Value) : null;

JsonObject Series(JsonNode m)
{
    var id = (string)m["id"]!;
    var a = m["attributes"]!;
    var rel = m["relationships"]?.AsArray() ?? new JsonArray();
    JsonNode? Rel(string type) => rel.FirstOrDefault(r => (string?)r?["type"] == type);
    var cover = (string?)Rel("cover_art")?["attributes"]?["fileName"];
    var genres = a["tags"]?.AsArray().Select(t => (JsonNode?)Pick(t?["attributes"]?["name"])).ToArray() ?? [];
    return new JsonObject
    {
        ["id"] = id,
        ["title"] = Pick(a["title"]),
        ["summary"] = Pick(a["description"]),
        ["status"] = (string?)a["status"],
        ["genres"] = new JsonArray(genres),
        ["author"] = (string?)Rel("author")?["attributes"]?["name"],
        ["cover"] = cover is null ? null : $"https://uploads.mangadex.org/covers/{id}/{cover}.256.jpg",
        ["url"] = $"https://mangadex.org/title/{id}",
        ["updatedAt"] = (string?)a["updatedAt"],
    };
}

async Task<JsonArray> Listing(string page, params (string, string)[] extra)
{
    var query = new List<(string, string)>
    {
        ("limit", PerPage.ToString()),
        ("offset", ((int.Parse(page) - 1) * PerPage).ToString()),
        ("includes[]", "cover_art"),
        ("availableTranslatedLanguage[]", Lang),
    };
    query.AddRange(extra);
    var r = await Get("/manga", query.ToArray());
    return new JsonArray(r["data"]!.AsArray().Select(m => (JsonNode?)Series(m!)).ToArray());
}

async Task<JsonArray> Chapters(string id)
{
    var list = new JsonArray();
    for (var offset = 0; ;)
    {
        var r = await Get($"/manga/{id}/feed", ("limit", "500"), ("offset", offset.ToString()), ("translatedLanguage[]", Lang),
            ("order[chapter]", "asc"), ("includes[]", "scanlation_group"));
        var data = r["data"]!.AsArray();
        foreach (var c in data)
        {
            var a = c!["attributes"]!;
            if (a["externalUrl"] is not null) continue; // hosted elsewhere: no pages here
            var groups = c["relationships"]!.AsArray()
                .Where(g => (string?)g?["type"] == "scanlation_group" && g?["attributes"] is not null)
                .Select(g => (string)g!["attributes"]!["name"]!);
            var scanlator = string.Join(" & ", groups);
            list.Add((JsonNode)new JsonObject
            {
                ["id"] = (string)c["id"]!,
                ["number"] = (string?)a["chapter"],
                ["title"] = (string?)a["title"],
                ["lang"] = (string?)a["translatedLanguage"],
                ["publishedAt"] = (string?)a["publishAt"],
                ["scanlator"] = scanlator.Length > 0 ? scanlator : null,
            });
        }
        offset += data.Count;
        if (data.Count == 0 || offset >= (int)r["total"]!) return list;
    }
}

async Task<JsonArray> Pages(string id)
{
    var r = await Get($"/at-home/server/{id}");
    var baseUrl = (string)r["baseUrl"]!;
    var chapter = r["chapter"]!;
    var hash = (string)chapter["hash"]!;
    return new JsonArray(chapter["data"]!.AsArray().Select(f => (JsonNode?)$"{baseUrl}/data/{hash}/{(string)f!}").ToArray());
}
