import socket, threading, unittest
import portscanner as ps


class T(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(ps.parse_ports("80,20-22"), [20, 21, 22, 80])
        with self.assertRaises(ValueError):
            ps.parse_ports("0")

    def test_scan_local_server(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        def serve():
            c, _ = srv.accept(); c.sendall(b"SSH-2.0-test\r\n"); c.close()
        threading.Thread(target=serve, daemon=True).start()
        res = ps.scan("127.0.0.1", [port], 1, 5, True)
        srv.close()
        self.assertEqual(res[0]["port"], port)
        self.assertEqual(res[0]["banner"], "SSH-2.0-test")


if __name__ == "__main__":
    unittest.main()
