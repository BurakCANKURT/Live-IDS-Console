# -*- coding: utf-8 -*-
"""
mini_vuln_target.py -- Native (Docker-siz), GERCEKTEN SQLi/XSS'e acik minik hedef.
SADECE 127.0.0.1'e baglanir (LAN'a KAPALI). Live-fire veri toplama kampanyasi icin,
Docker port-proxy'sinin loopback capture'da GORUNMEZ olmasi nedeniyle DVWA yerine kullanilir.
"""
import http.server
import socketserver
import sqlite3
import urllib.parse
import html
import os

import sys
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BIND = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
# DB dosya adina BIND de dahil edilir -- ayni PORT'ta, farkli IP'lere baglı iki
# instance (karma-istemci kampanyasi: 127.0.0.1 + vEthernet(WSL) IP) AYNI ANDA
# calisirsa, ikisi de init_db()'de os.remove+recreate yaptigi icin PORT-only
# isimlendirme yaris durumuna/kilitlenmeye yol acardi.
DB_PATH = os.path.join(os.path.dirname(__file__), "mini_vuln_%d_%s.db" % (PORT, BIND.replace(".", "_")))


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, first_name TEXT)")
    cur.executemany(
        "INSERT INTO users (id, username, password, first_name) VALUES (?,?,?,?)",
        [
            (1, "admin", "5f4dcc3b5aa765d61d8327deb882cf99", "admin"),
            (2, "gordonb", "e99a18c428cb38d5f260853678922e03", "Gordon"),
            (3, "1337", "8d3533d75ae2c3966d7e0d4fcc69216b", "Hack"),
            (4, "pablo", "0d107d09f5bbe40cade3de5c71e9e9b7", "Pablo"),
        ],
    )
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT)")
    cur.executemany(
        "INSERT INTO products (id, name, description) VALUES (?,?,?)",
        [(1, "Apple Juice", "juicy"), (2, "Banana Juice", "sweet"), (3, "Carrot Juice", "healthy")],
    )
    con.commit()
    con.close()


class VulnHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive -- yoksa her istek YENI TCP baglantisi acar,
    # nikto gibi hizli tarayicilarda distinct_conns >= CONN_FLOOD_MIN(200) tetiklenip
    # WebAttack yerine "Hacimsel SYN-Flood -> DoS" olarak yanlis sinifllanir (dogrulama R1 bulgusu).

    def log_message(self, fmt, *args):
        with open(os.path.join(os.path.dirname(__file__), "mini_vuln_access.log"), "a", encoding="utf-8") as f:
            f.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/" or path == "/index.php" or path == "/login.php":
            self._send(200, "<html><body><h1>Home</h1><p>OK</p></body></html>")
            return

        if path == "/vulnerabilities/sqli/":
            # GERCEK, string-birlestirmeli (kasitli aciik) SQLi -- DVWA 'low' tarzi.
            idv = qs.get("id", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            query = "SELECT first_name, username FROM users WHERE id = '%s'" % idv
            try:
                cur.execute(query)
                rows = cur.fetchall()
                body = "<html><body><h1>SQLi Result</h1>"
                for r in rows:
                    body += "<p>ID: %s First name: %s Surname: %s</p>" % (idv, html.escape(str(r[0])), html.escape(str(r[1])))
                body += "</body></html>"
                self._send(200, body)
            except sqlite3.Error as e:
                # gercek SQL hata mesajini don -- error-based teknik icin gerekli
                self._send(200, "<html><body>You have an error in your SQL syntax: %s</body></html>" % html.escape(str(e)))
            con.close()
            return

        if path == "/vulnerabilities/xss_r/":
            name = qs.get("name", [""])[0]
            # KASITLI KACIRILMAMIS -- gercek yansitilan XSS
            self._send(200, "<html><body><h1>Hello %s</h1></body></html>" % name)
            return

        if path == "/rest/products/search":
            qv = qs.get("q", [""])[0]
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            query = "SELECT id, name, description FROM products WHERE name LIKE '%%%s%%'" % qv
            try:
                cur.execute(query)
                rows = cur.fetchall()
                body = "{\"data\": [" + ",".join(
                    "{\"id\":%s,\"name\":\"%s\"}" % (r[0], html.escape(str(r[1]))) for r in rows
                ) + "]}"
                self._send(200, body, ctype="application/json")
            except sqlite3.Error as e:
                self._send(200, "{\"error\": \"%s\"}" % str(e).replace('"', "'"), ctype="application/json")
            con.close()
            return

        if path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /vulnerabilities/\n", ctype="text/plain")
            return

        self._send(404, "<html><body>404 Not Found</body></html>")


if __name__ == "__main__":
    init_db()
    with socketserver.ThreadingTCPServer((BIND, PORT), VulnHandler) as httpd:
        print("mini_vuln_target listening on %s:%s (loopback only)" % (BIND, PORT))
        httpd.serve_forever()
