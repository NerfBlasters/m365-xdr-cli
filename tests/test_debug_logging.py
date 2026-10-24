"""Signed transfer secrets stay private even with debug diagnostics enabled."""

import io
import logging

import httpx

from xdr_cli._debug_logging import PrivateDebugFormatter, URLRedactionFilter


def test_actual_debug_setup_keeps_httpx_bearer_urls_out_of_stderr(monkeypatch):
    from xdr_cli.main import _setup_debug_logging

    stream = io.StringIO()
    monkeypatch.setattr("sys.stderr", stream)
    names = ("httpx", "msal", "xdr_cli")
    previous = {
        name: (logging.getLogger(name).level, logging.getLogger(name).handlers[:],
               logging.getLogger(name).filters[:])
        for name in names
    }
    try:
        _setup_debug_logging()
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as c:
            c.get("https://example.blob.core.windows.net/file?sig=PRIVATE_SETUP_SECRET")
    finally:
        for name, (level, handlers, filters) in previous.items():
            logger = logging.getLogger(name)
            logger.setLevel(level)
            logger.handlers, logger.filters = handlers, filters
    assert "HTTP Request" in stream.getvalue()
    assert "PRIVATE_SETUP_SECRET" not in stream.getvalue()


def test_httpx_real_debug_handler_hides_signed_queries_and_credentials():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(URLRedactionFilter())
    handler.setFormatter(PrivateDebugFormatter("%(name)s %(message)s"))
    logger = logging.getLogger("httpx")
    level, handlers, propagate = logger.level, logger.handlers[:], logger.propagate
    logger.handlers, logger.propagate = [handler], False
    logger.setLevel(logging.DEBUG)
    try:
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as c:
            c.get("https://example.blob.core.windows.net/logs?sig=SYNTHETIC_SAS_SECRET")
            c.get("https://security.microsoft.com/apiproxy/mtp/liveResponseApi/download_file"
                  "?token=SYNTHETIC_DOWNLOAD_SECRET")
            c.get("https://user:SYNTHETIC_URL_PASSWORD@example.com/path?secret=VALUE#fragment")
    finally:
        logger.setLevel(level)
        logger.handlers, logger.propagate = handlers, propagate
    rendered = stream.getvalue()
    assert "example.blob.core.windows.net/logs" in rendered
    assert "liveResponseApi/download_file" in rendered
    assert "SYNTHETIC" not in rendered and "VALUE" not in rendered
    assert "fragment" not in rendered and "user:" not in rendered


def test_debug_formatter_hides_urls_in_exception_tracebacks():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(PrivateDebugFormatter("%(message)s"))
    record = logging.LogRecord("httpx", logging.DEBUG, "test", 1, "failed", (), None)
    try:
        raise ValueError("https://example.com/result?sig=SYNTHETIC_TRACEBACK_SECRET")
    except ValueError:
        import sys

        record.exc_info = sys.exc_info()
    handler.handle(record)
    assert "example.com/result" in stream.getvalue()
    assert "SYNTHETIC_TRACEBACK_SECRET" not in stream.getvalue()


def test_unformattable_debug_record_does_not_fall_back_to_raw_arguments():
    record = logging.LogRecord("httpx", logging.DEBUG, "test", 1, "%d", ("PRIVATE",), None)
    assert URLRedactionFilter().filter(record)
    assert "PRIVATE" not in record.getMessage()
    assert "omitted" in PrivateDebugFormatter().format(record)
