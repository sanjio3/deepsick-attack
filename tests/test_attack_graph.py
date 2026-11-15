"""攻击图的单元测试。

重点验证三件事，它们正是旧实现三连败的直接原因：
1. 入口能从真实响应里被抽出来，参数语义判断正确（a-05 的 id 是文件名 → file）；
2. 边由入口属性派生，不是穷举 payload 表；
3. 拿到能力后 flag_hunt 会被派生出来并且排在最前（不再回头挖洞）。
"""
import unittest

from deepsick_attack import graph_exec
from deepsick_attack.attack_graph import (
    AttackGraph,
    Edge,
    Entry,
    classify_param,
    derive,
    extract_entries,
)

DASHBOARD_HTML = """
<html><body>
<a href="/logout.php">退出登录</a>
<a href="/download.php?id=CONTRACT-2024-001.pdf">下载合同</a>
<a href="https://cdn.bootcdn.net/ajax/libs/x.css">css</a>
<form action="/upload.php" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="text" name="title">
</form>
</body></html>
"""

SEARCH_HTML = """
<form action="/assets" method="GET">
  <input type="text" name="q" placeholder="搜索资产">
</form>
"""


class ClassifyParamTest(unittest.TestCase):
    def test_file_extension_wins_on_file_param_name(self):
        # id 的值是 .pdf，说明服务端拿它当路径用
        self.assertEqual(classify_param("id", "CONTRACT-2024-001.pdf"), "file")

    def test_search_names(self):
        self.assertEqual(classify_param("q"), "search")
        self.assertEqual(classify_param("keyword"), "search")

    def test_redirect_names(self):
        self.assertEqual(classify_param("next"), "redirect")

    def test_plain_id_stays_id(self):
        self.assertEqual(classify_param("id", "1"), "id")


class ExtractEntriesTest(unittest.TestCase):
    def test_pulls_download_with_file_semantics(self):
        entries = {e.path: e for e in extract_entries(DASHBOARD_HTML)}
        self.assertIn("/download.php", entries)
        self.assertEqual(entries["/download.php"].params.get("id"), "file")

    def test_pulls_upload_form_with_method_and_flag(self):
        entries = [e for e in extract_entries(DASHBOARD_HTML) if e.path == "/upload.php"]
        self.assertTrue(entries)
        self.assertEqual(entries[0].method, "POST")
        self.assertTrue(entries[0].has_upload)

    def test_search_form_yields_search_param(self):
        entries = {e.path: e for e in extract_entries(SEARCH_HTML)}
        self.assertIn("/assets", entries)
        self.assertEqual(entries["/assets"].params.get("q"), "search")

    def test_drops_root_and_placeholders(self):
        entries = extract_entries('<a href="#">x</a><a href="/">y</a>')
        self.assertFalse([e for e in entries if e.path in ("/", "#")])


class DeriveTest(unittest.TestCase):
    def test_file_param_derives_lfi_only(self):
        edge = derive(Entry("GET", "/download.php", {"id": "file"}))
        self.assertEqual([e.family for e in edge], ["lfi"])

    def test_search_param_derives_ssti_and_sqli(self):
        fams = {e.family for e in derive(Entry("GET", "/assets", {"q": "search"}))}
        self.assertEqual(fams, {"ssti", "sqli"})

    def test_id_param_derives_idor(self):
        fams = {e.family for e in derive(Entry("GET", "/asset", {"id": "id"}))}
        self.assertEqual(fams, {"idor"})

    def test_upload_form_derives_upload_bypass(self):
        fams = {e.family for e in derive(
            Entry("POST", "/upload.php", {"file": "file"}, has_upload=True))}
        self.assertIn("upload_bypass", fams)


class GraphTest(unittest.TestCase):
    def _graph_with_lfi_found(self) -> AttackGraph:
        graph = AttackGraph()
        graph.add_entries([Entry("GET", "/download.php", {"id": "file"})])
        graph.add_capability("file_read", "GET:/download.php?id")
        return graph

    def test_capability_creates_flag_hunt_bound_to_same_entry(self):
        graph = self._graph_with_lfi_found()
        hunt = [e for e in graph.edges.values() if e.family == "flag_hunt"]
        self.assertEqual(len(hunt), 1)
        # 关键：flag_hunt 必须挂在刚才那个入口上，才能复用它的参数直接读 flag
        self.assertIsNotNone(hunt[0].entry)
        self.assertEqual(hunt[0].entry.path, "/download.php")

    def test_flag_hunt_ranks_before_everything(self):
        graph = AttackGraph()
        graph.add_entries([Entry("GET", "/search", {"q": "search"})])
        graph.add_capability("file_read", "GET:/search?q")
        self.assertEqual(graph.next_edge().family, "flag_hunt")

    def test_closed_edge_never_returns(self):
        graph = AttackGraph()
        graph.add_entries([Entry("GET", "/download.php", {"id": "file"})])
        edge = graph.next_edge()
        graph.close(edge)
        self.assertNotEqual(graph.next_edge(), edge)

    def test_auth_reopens_denied_entries(self):
        graph = AttackGraph()
        graph.add_entries([Entry("GET", "/assets", {"q": "search"}, auth="denied")])
        # 把所有待验证边都关掉，模拟「未登录时全试过、全失败」
        while True:
            edge = graph.next_edge()
            if edge is None:
                break
            graph.close(edge)
        self.assertIsNone(graph.next_edge())
        graph.add_capability("auth", "session")
        again = graph.next_edge()
        self.assertIsNotNone(again)
        self.assertEqual(again.state, "pending")

    def test_stats_track_progress(self):
        graph = self._graph_with_lfi_found()
        stats = graph.stats()
        self.assertEqual(stats["entries"], 1)
        self.assertEqual(stats["caps"], 1)
        self.assertGreaterEqual(stats["pending"], 2)


class RenderTest(unittest.TestCase):
    def test_lfi_render_is_single_line_with_payloads(self):
        edge = Edge("lfi", Entry("GET", "/download.php", {"id": "file"}))
        cmd = graph_exec.render(edge, "http://10.0.0.1")
        self.assertIn("../../../../etc/passwd", cmd)
        self.assertIn("challenge/flag.txt", cmd)
        # 单行是硬要求：JSON 里带裸换行会把命令弄坏
        self.assertNotIn("\n", cmd)

    def test_auth_render_harvests_links(self):
        edge = Edge("auth", Entry("POST", "/login.php",
                                 {"username": "generic", "password": "generic"}))
        cmd = graph_exec.render(edge, "http://10.0.0.1")
        self.assertIn("LOGIN_OK", cmd)
        # 登录后必须顺手抓入口，否则图还是空的
        self.assertIn("href=", cmd)

    def test_upload_bypass_has_no_renderer_yet(self):
        edge = Edge("upload_bypass", Entry("POST", "/upload.php",
                                          {"file": "file"}, has_upload=True))
        self.assertIsNone(graph_exec.render(edge, "http://10.0.0.1"))


class JudgeTest(unittest.TestCase):
    def _lfi_edge(self) -> Edge:
        return Edge("lfi", Entry("GET", "/download.php", {"id": "file"}))

    def test_passwd_content_proves_file_read(self):
        verdict = graph_exec.judge(
            self._lfi_edge(), "### x 200 922\nroot:x:0:0:root:/root:/bin/bash")
        self.assertEqual(verdict["state"], "worked")
        self.assertEqual(verdict["caps"][0][0], "file_read")
        self.assertEqual(verdict["caps"][0][1], "GET:/download.php?id")

    def test_flag_in_output_short_circuits(self):
        verdict = graph_exec.judge(self._lfi_edge(), "flag{075b323e-f897}")
        self.assertEqual(verdict["state"], "worked")
        self.assertTrue(verdict["flags"])

    def test_no_proof_means_failed(self):
        verdict = graph_exec.judge(self._lfi_edge(), "### x 404 24\nNot Found")
        self.assertEqual(verdict["state"], "failed")

    def test_auth_ok_creates_capability(self):
        edge = Edge("auth", Entry("POST", "/login.php", {"username": "generic"}))
        verdict = graph_exec.judge(edge, "employee:employee123 => 302 /dashboard.php\nLOGIN_OK employee:employee123")
        self.assertEqual(verdict["state"], "worked")
        self.assertEqual(verdict["caps"][0][0], "auth")

    def test_auth_failure_is_not_success(self):
        edge = Edge("auth", Entry("POST", "/login.php", {"username": "generic"}))
        verdict = graph_exec.judge(edge, "admin:admin => 200 /login.php")
        self.assertEqual(verdict["state"], "failed")


if __name__ == "__main__":
    unittest.main()
