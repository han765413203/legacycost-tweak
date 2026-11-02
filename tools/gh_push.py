#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
走 GitHub REST API 推代码 —— 专门对付 git push 被代理掐死的情况

用法:
    python3 tools/gh_push.py <owner/repo> <token> [分支名]

原理:
    1. 每个文件 POST /git/blobs 拿 sha
    2. 一次性 POST /git/trees 建树
    3. POST /git/commits 建提交
    4. POST/PATCH /git/refs 更新分支
"""
import base64
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

API = "https://api.github.com"


def req(method, path, token, payload=None):
    url = API + path
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", "Bearer " + token)
    r.add_header("Accept", "application/vnd.github+json")
    r.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body.strip() else {})
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}


def git_files(root):
    out = subprocess.check_output(["git", "ls-files"], cwd=root).decode()
    return [l for l in out.splitlines() if l.strip()]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    repo = sys.argv[1]           # owner/name
    token = sys.argv[2]
    branch = sys.argv[3] if len(sys.argv) > 3 else "main"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    files = git_files(root)
    print(f"仓库: {repo}  分支: {branch}  文件数: {len(files)}")

    # 0) 空仓库得先初始化一次，不然 /git/blobs 直接 409
    code, res = req("GET", f"/repos/{repo}/git/ref/heads/{branch}", token)
    if code in (404, 409):   # 409 = Git Repository is empty
        print("  仓库是空的，先塞一个占位文件初始化 ...")
        code2, res2 = req("PUT", f"/repos/{repo}/contents/.bootstrap", token, {
            "message": "init",
            "content": base64.b64encode(b"bootstrap\n").decode(),
            "branch": branch,
        })
        if code2 not in (200, 201):
            print(f"!! 初始化失败: {code2} {res2}")
            sys.exit(1)
        print(f"  初始化完成: {res2['commit']['sha'][:8]}")

    # 1) blobs
    tree = []
    for i, rel in enumerate(files, 1):
        full = os.path.join(root, rel)
        with open(full, "rb") as f:
            content = f.read()
        code, res = req("POST", f"/repos/{repo}/git/blobs", token, {
            "content": base64.b64encode(content).decode(),
            "encoding": "base64",
        })
        if code not in (200, 201):
            print(f"  !! blob 失败 {rel}: {code} {res}")
            sys.exit(1)
        mode = "100755" if rel.endswith(".sh") else "100644"
        tree.append({"path": rel, "mode": mode, "type": "blob", "sha": res["sha"]})
        print(f"  [{i:2d}/{len(files)}] {rel}  ({len(content)} bytes)")

    # 2) tree（全量建树，不挂 base_tree，占位文件自然就不在了）
    code, res = req("POST", f"/repos/{repo}/git/trees", token, {"tree": tree})
    if code not in (200, 201):
        print(f"!! tree 失败: {code} {res}")
        sys.exit(1)
    tree_sha = res["sha"]
    print(f"tree = {tree_sha}")

    # 3) commit（父提交取当前 HEAD）
    parents = []
    code, head = req("GET", f"/repos/{repo}/git/ref/heads/{branch}", token)
    if code == 200:
        parents = [head["object"]["sha"]]

    code, res = req("POST", f"/repos/{repo}/git/commits", token, {
        "message": "负之遗产 1.0.9 iOS 修改器\n\n"
                   "- IL2CPP metadata 解析 + 注册表定位，全套 RVA\n"
                   "- 存档键名对照表（材料/草/木/布/铁/石/魂/宝珠）\n"
                   "- Theos 工程 + Mach-O 注入器 + IPA 打包器\n"
                   "- GitHub Actions 云端编译",
        "tree": tree_sha,
        "parents": parents,
    })
    if code not in (200, 201):
        print(f"!! commit 失败: {code} {res}")
        sys.exit(1)
    commit_sha = res["sha"]
    print(f"commit = {commit_sha}")

    # 4) ref
    code, res = req("PATCH", f"/repos/{repo}/git/refs/heads/{branch}", token,
                    {"sha": commit_sha, "force": True})
    if code not in (200, 201):
        print(f"  PATCH 失败 ({code})，改用 POST 建分支")
        code, res = req("POST", f"/repos/{repo}/git/refs", token,
                        {"ref": f"refs/heads/{branch}", "sha": commit_sha})
        if code not in (200, 201):
            print(f"!! 建分支失败: {code} {res}")
            sys.exit(1)
    print(f"分支 {branch} -> {commit_sha}")
    print(f"\n完成: https://github.com/{repo}")


if __name__ == "__main__":
    main()
