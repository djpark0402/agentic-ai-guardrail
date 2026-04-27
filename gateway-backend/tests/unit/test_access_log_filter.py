"""uvicorn.access 로그에서 /health 경로를 걸러내는 필터 단위 테스트.

도커 healthcheck 가 수초마다 찍는 ``'"GET /health HTTP/1.1" 200 OK'``
스팸을 제거해 운영 로그 가독성을 유지한다. uvicorn 을 실제로 띄우지
않고 ``logging.LogRecord`` 를 수동 구성해 필터 로직만 검증한다.
"""

from __future__ import annotations

import logging

from app.main import _HealthAccessLogFilter

# uvicorn.access 가 실제로 사용하는 레코드 템플릿. getMessage() 호출 시
# args 와 함께 포맷되어 '127.0.0.1:53594 - "GET /health HTTP/1.1" 200'
# 같은 문자열이 된다.
_UVICORN_ACCESS_TEMPLATE = '%s - "%s %s HTTP/%s" %d'


def _make_access_record(
    *,
    template: str = _UVICORN_ACCESS_TEMPLATE,
    args: tuple | None,
) -> logging.LogRecord:
    """uvicorn.access 로거가 만드는 LogRecord 를 흉내낸 헬퍼."""
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg=template,
        args=args,
        exc_info=None,
    )


def test_health_access_record_is_filtered_out() -> None:
    """uvicorn access 포맷 args 에 /health path 가 들어오면 필터가 차단."""
    record = _make_access_record(
        args=("127.0.0.1:53594", "GET", "/health", "1.1", 200),
    )
    assert _HealthAccessLogFilter().filter(record) is False


def test_non_health_access_record_passes() -> None:
    """실제 요청 경로는 필터를 통과한다."""
    record = _make_access_record(
        args=(
            "192.168.32.1:43362",
            "POST",
            "/v1/chat/completions",
            "1.1",
            200,
        ),
    )
    assert _HealthAccessLogFilter().filter(record) is True


def test_filter_falls_back_to_message_string() -> None:
    """args 가 비어도 포맷된 message 에 /health 가 있으면 차단된다.

    uvicorn 버전이 바뀌어 args 구성이 달라지는 경우에 대비한 폴백 경로.
    """
    record = _make_access_record(
        template='127.0.0.1:48326 - "GET /health HTTP/1.1" 200 OK',
        args=None,
    )
    assert _HealthAccessLogFilter().filter(record) is False


def test_filter_attached_to_uvicorn_access_logger_on_import() -> None:
    """app.main import 시점에 uvicorn.access 로거에 필터가 부착된다."""
    import app.main  # noqa: F401 (import 부작용 검증 목적)

    access_logger = logging.getLogger("uvicorn.access")
    assert any(
        isinstance(f, _HealthAccessLogFilter) for f in access_logger.filters
    ), "uvicorn.access 로거에 _HealthAccessLogFilter 가 부착돼 있어야 한다."
