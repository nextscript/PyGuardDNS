import struct
import threading
import time
from unittest.mock import MagicMock, patch

import app


def _make_dot_upstream(**overrides):
    upstream = {
        "id": 1,
        "name": "test-dot",
        "address": "1.1.1.1",
        "port": 853,
        "resolver_type": "dot",
        "transport": "tls",
        "resolver": "tls://1.1.1.1",
        "hostname": "",
        "tls_name": "",
        "latency_ms": None,
    }
    upstream.update(overrides)
    return upstream


def test_dot_connection_sends_length_prefix():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    mock_sock.recv.side_effect = [struct.pack("!H", 12), b"\x00" * 12]

    request = b"\x00" * 16
    conn._send_and_receive(request, timeout=3.0)

    sent = mock_sock.sendall.call_args[0][0]
    assert len(sent) == 2 + len(request)
    prefix = struct.unpack("!H", sent[:2])[0]
    assert prefix == len(request)
    assert sent[2:] == request


def test_dot_connection_reads_length_prefix():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    response_body = b"test response"
    mock_sock.recv.side_effect = [
        struct.pack("!H", len(response_body)),
        response_body,
    ]

    result = conn._send_and_receive(b"\x00" * 16, timeout=3.0)
    assert result == response_body


def test_dot_connection_reuse_on_second_query():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    conn.last_used = time.time()
    orig_reuse = conn.reuse_count
    mock_sock.recv.side_effect = [struct.pack("!H", 12), b"\x00" * 12]

    conn.query(b"\x00" * 16, timeout=3.0)
    assert conn.reuse_count == orig_reuse + 1


def test_dot_connection_error_count_increments():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.last_used = time.time()

    with patch.object(conn, "connect") as mock_connect:
        mock_connect.side_effect = OSError("connect failed")
        conn.conn = mock_sock
        mock_sock.sendall.side_effect = OSError("send failed")

        import pytest
        with pytest.raises(OSError):
            conn.query(b"\x00" * 16, timeout=3.0)

        assert conn.error_count >= 1
        assert conn.reconnect_count >= 1
        assert mock_connect.call_count >= 1


def test_dot_connection_reconnect_on_idle_timeout():
    conn = app.DotConnection(_make_dot_upstream(), idle_timeout=0.1)
    mock_sock = MagicMock()
    conn.conn = mock_sock
    conn.last_used = time.time() - 10

    orig_reuse = conn.reuse_count

    with patch.object(conn, "connect") as mock_connect:
        mock_sock.recv.side_effect = [struct.pack("!H", 12), b"\x00" * 12]
        conn._send_and_receive(b"\x00" * 16, timeout=3.0)

        assert conn.reuse_count == orig_reuse
        mock_connect.assert_not_called()

    with patch.object(conn, "connect") as mock_connect:
        mock_connect.return_value = None
        conn.last_used = time.time() - 10
        mock_sock2 = MagicMock()
        conn.conn = mock_sock2
        mock_sock2.recv.side_effect = [struct.pack("!H", 12), b"\x00" * 12]

        conn._ensure_connected(timeout=3.0)
        mock_connect.assert_called_once()


def test_dot_connection_invalid_short_response():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    mock_sock.recv.side_effect = [struct.pack("!H", 3), b"abc"]

    import pytest
    with pytest.raises(OSError, match="invalid short DoT response"):
        conn._send_and_receive(b"\x00" * 16, timeout=3.0)


def test_dot_connection_recv_exact():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    mock_sock.recv.side_effect = [b"ab", b"cd"]

    result = conn._recv_exact(4)
    assert result == b"abcd"
    assert mock_sock.recv.call_count == 2


def test_dot_connection_recv_exact_eof():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    mock_sock.recv.return_value = b""

    import pytest
    with pytest.raises(OSError, match="short DoT DNS response"):
        conn._recv_exact(4)


def test_dot_connection_close():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock

    conn.close()
    mock_sock.close.assert_called_once()
    assert conn.conn is None


def test_dot_connection_close_idempotent():
    conn = app.DotConnection(_make_dot_upstream())
    conn.conn = None
    conn.close()


def test_dot_connection_metrics():
    conn = app.DotConnection(_make_dot_upstream())
    conn.handshake_count = 5
    conn.reuse_count = 10
    conn.reconnect_count = 2
    conn.error_count = 1

    m = conn.metrics()
    assert m["tls_handshake_count"] == 5
    assert m["dot_reuse_count"] == 10
    assert m["dot_reconnect_count"] == 2
    assert m["dot_error_count"] == 1


def test_dot_pool_key():
    upstream = _make_dot_upstream(id=99, resolver="tls://cloudflare-dns.com", address="1.1.1.1", port=853)
    key = app._dot_pool_key(upstream)
    assert "99" in key
    assert "1.1.1.1" in key
    assert "853" in key


def test_dot_pool_key_differs_by_resolver():
    u1 = _make_dot_upstream(id=1, resolver="tls://cloudflare-dns.com", address="1.1.1.1", port=853)
    u2 = _make_dot_upstream(id=2, resolver="tls://dns.google", address="1.1.1.1", port=853)
    assert app._dot_pool_key(u1) != app._dot_pool_key(u2)


def test_query_dot_upstream_pooled_creates_pool():
    upstream = _make_dot_upstream(id=99)
    key = app._dot_pool_key(upstream)

    with app.dot_pools_lock:
        if key in app.dot_pools:
            del app.dot_pools[key]

    with patch.object(app.DotConnection, "query", return_value=b"\x00" * 12):
        result = app.query_dot_upstream_pooled(upstream, b"\x00" * 16, timeout=3.0)
        assert result == b"\x00" * 12

    with app.dot_pools_lock:
        assert key in app.dot_pools
        pool = app.dot_pools[key]
        assert isinstance(pool, app.DotConnection)


def test_query_dot_upstream_delegates_to_pooled():
    upstream = _make_dot_upstream(id=1)
    with patch("app.query_dot_upstream_pooled", return_value=b"\x00" * 12) as mock_pooled:
        result = app.query_dot_upstream(upstream, b"\x00" * 16, timeout=3.0)
        assert result == b"\x00" * 12
        mock_pooled.assert_called_once_with(upstream, b"\x00" * 16, timeout=3.0)


def test_dot_pool_metrics():
    with app.dot_pools_lock:
        saved = dict(app.dot_pools)
        app.dot_pools.clear()
        try:
            m = app.dot_pool_metrics()
            assert isinstance(m, dict)
            assert "dot_pool_size" in m
            assert m["dot_pool_size"] == 0
            assert "tls_handshake_count" in m
        finally:
            app.dot_pools.update(saved)


def test_dot_connect_candidate_ips():
    conn = app.DotConnection(_make_dot_upstream(address="1.1.1.1"))
    ips = conn._candidate_ips()
    assert "1.1.1.1" in ips


def test_healthcheck_uses_real_resolver_type():
    query = b"\x00" * 12
    upstream_dot = _make_dot_upstream(id=1, resolver_type="dot", address="1.1.1.1", port=853)
    upstream_plain = _make_dot_upstream(id=2, resolver_type="plain_udp", transport="udp", address="1.1.1.1", port=53)

    query_funcs = []

    def tracked_query_dot(upstream, request, timeout=4.0):
        query_funcs.append(("dot", upstream["id"]))
        return b"\x00" * 12

    def tracked_query_plain(upstream, request, timeout=5.0):
        query_funcs.append(("plain", upstream["id"]))
        return b"\x00" * 12

    with patch("app.query_dot_upstream", side_effect=tracked_query_dot):
        with patch("app.query_plain_upstream", side_effect=tracked_query_plain):
            app._query_one_upstream(upstream_dot, query, update_metrics=False)
            app._query_one_upstream(upstream_plain, query, update_metrics=False)

    assert ("dot", 1) in query_funcs
    assert ("plain", 2) in query_funcs


def test_log_query_does_not_block():
    app.db_write_queue.clear()
    request = b"\x00" * 16
    response = app.handle_dns_request(request, "127.0.0.1", "UDP")
    assert response is not None


def test_dot_connection_thread_safety():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock
    conn.last_used = time.time()

    recv_results = iter([struct.pack("!H", 12), b"\x00" * 12])
    def recv_side_effect(n):
        try:
            return next(recv_results)
        except StopIteration:
            return struct.pack("!H", 12)
    mock_sock.recv.side_effect = recv_side_effect

    errors = []

    def query_thread():
        try:
            conn.query(b"\x00" * 16, timeout=3.0)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=query_thread) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0


def test_dot_connection_send_large_request():
    conn = app.DotConnection(_make_dot_upstream())
    mock_sock = MagicMock()
    conn.conn = mock_sock

    import pytest
    with pytest.raises(OSError, match="DoT DNS request too large"):
        conn._send_and_receive(b"\x00" * 65536, timeout=3.0)


def test_dot_tls_server_name_known():
    assert app.dot_tls_server_name("1.1.1.1") == "cloudflare-dns.com"
    assert app.dot_tls_server_name("8.8.8.8") == "dns.google"
    assert app.dot_tls_server_name("9.9.9.9") == "dns.quad9.net"


def test_dot_tls_server_name_unknown():
    result = app.dot_tls_server_name("192.168.1.1")
    assert result == "192.168.1.1"


def test_query_dot_upstream_once_fallback():
    upstream = _make_dot_upstream(address="1.1.1.1", port=853)
    with patch("app.socket.create_connection") as mock_create:
        with patch("app.ssl.create_default_context") as mock_ssl:
            mock_sock = MagicMock()
            mock_create.return_value = mock_sock
            mock_ssl_ctx = MagicMock()
            mock_ssl.return_value = mock_ssl_ctx
            mock_tls_sock = MagicMock()
            mock_ssl_ctx.wrap_socket.return_value = mock_tls_sock
            mock_tls_sock.recv.side_effect = [b"\x00\x0c", b"\x00" * 12]

            result = app.query_dot_upstream_once(upstream, b"\x00" * 16, timeout=4.0)
            assert result == b"\x00" * 12
