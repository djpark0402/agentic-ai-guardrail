"""Pytest 전역 설정.

테스트 실행 시 HuggingFace Hub / transformers / datasets 오프라인
모드를 강제하여 테스트 중 네트워크를 통한 모델·데이터셋 다운로드가
일어나지 않도록 방어한다. 실수로 ``AutoModel.from_pretrained("hf/hub-id")``
같이 원격 ID 를 참조하더라도 다운로드 대신 ``OSError`` 로 실패하므로
의도치 않은 디스크·네트워크 사용을 조기에 차단한다.

환경변수는 ``setdefault`` 로 설정하므로 사용자가 의도적으로 ``0`` 을
지정한 경우에는 덮어쓰지 않는다.
"""

import os

# transformers / huggingface_hub / datasets 가 import 되기 전에 설정돼야
# 오프라인 플래그가 반영된다. conftest.py 는 pytest 가 테스트 수집 이전에
# 가장 먼저 import 하므로 여기에 두는 것이 안전하다.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
