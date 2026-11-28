"""Download only the pinned successful catalog artifact in GitHub CI."""
from pathlib import Path
import argparse, hashlib, json, os, urllib.parse, urllib.request
URL = "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14194828118/zip"
EXPECTED_BYTES = 95269620
EXPECTED_SHA = "32e325c73e8a47ee14683ff96dec87bf505c1e7ce2fff56af509aacc1b51e6a5"
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("artifact redirect must retain HTTPS")
        child = super().redirect_request(request, response, code, message, headers, newurl)
        if child is not None:
            child.remove_header("Authorization")
        return child
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Artifact retrieval is configured only for GitHub CI.")
    token = os.environ.get("GET_INFO_GITHUB_TOKEN")
    if not token: raise ValueError("missing read-only GitHub artifact token")
    target = a.output.absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists(): raise ValueError("fresh artifact output required")
    request = urllib.request.Request(URL, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    digest, count = hashlib.sha256(), 0
    partial = target.with_name(target.name + ".partial")
    with urllib.request.build_opener(Redirect()).open(request, timeout=60) as response:
        with partial.open("xb") as output:
            while True:
                block = response.read(1 << 20)
                if not block: break
                count += len(block); digest.update(block); output.write(block)
            output.flush(); os.fsync(output.fileno())
    if count != EXPECTED_BYTES or digest.hexdigest() != EXPECTED_SHA:
        raise ValueError("reference artifact complete ZIP identity differs")
    partial.rename(target)
    print(json.dumps(dict(artifact=14194828118, bytes=count, sha256=digest.hexdigest())))
if __name__ == "__main__": main()
