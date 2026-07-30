from __future__ import annotations

import pytest

from opencode_guardian.contracts import Stage, normalize_packet
from opencode_guardian.errors import GuardError


def packet() -> dict[str, object]:
    return {
        "certainty": {"confirmed": True, "unresolved_items": [], "assumptions": []},
        "requirements": [
            {
                "id": "R1",
                "statement": "实现受控修改。",
                "acceptance_ids": ["A1"],
            }
        ],
        "acceptance": [
            {
                "id": "A1",
                "criterion": "受控文件通过检查。",
                "verification": ["pytest"],
                "required_paths": ["src/app.py"],
            }
        ],
        "constraints": ["未知工具默认拒绝。"],
        "non_goals": ["不修改外部项目。"],
        "stop_conditions": ["可信验证不可用。"],
        "architecture": {
            "objective": "最小受控开发链路。",
            "public_interface": "Application",
            "dependency_direction": "adapter -> application -> domain",
            "components": [
                {
                    "name": "Application",
                    "responsibility": "编排。",
                    "dependencies": [],
                }
            ],
            "trust_boundaries": ["模型输入不可信。"],
            "data_flows": ["请求进入守卫后写入。"],
            "concurrency": {
                "ordering": "按 Run revision。",
                "idempotency": "按 call_id。",
                "backpressure": "有界请求。",
                "limits": "单消息一 MiB。",
                "failures": "失败关闭。",
                "scaling": "按 Run 扩展。",
                "observability": "记录事件摘要。",
            },
        },
        "phases": [
            {
                "id": "P1",
                "goal": "实现。",
                "requirement_ids": ["R1"],
                "acceptance_ids": ["A1"],
                "allowed_paths": ["src/**"],
                "check_ids": ["pytest"],
            }
        ],
    }


def test_stage_surface_is_minimal() -> None:
    assert [stage.value for stage in Stage] == [
        "PLANNING",
        "IMPLEMENTING",
        "VERIFYING",
        "REVIEW_REQUIRED",
        "ACCEPTED",
    ]


def test_packet_is_frozen_as_one_validated_contract() -> None:
    normalized = normalize_packet(packet(), available_checks={"pytest"})
    assert normalized["phases"][0]["allowed_paths"] == ["src/**"]


def test_packet_rejects_unknown_check() -> None:
    value = packet()
    value["phases"][0]["check_ids"] = ["invented"]
    with pytest.raises(GuardError, match="registered"):
        normalize_packet(value, available_checks={"pytest"})


def test_packet_requires_acceptance_paths_to_be_covered() -> None:
    value = packet()
    value["phases"][0]["allowed_paths"] = ["tests/**"]
    with pytest.raises(GuardError, match="required path"):
        normalize_packet(value, available_checks={"pytest"})


@pytest.mark.parametrize(
    "term",
    [
        "暂定",
        "待定",
        "不知道",
        "未检查",
        "待确认",
        "后续处理",
        "视情况",
        "可能",
        "大概",
        "TBD",
        "TODO",
        "unknown",
        "not checked",
        "相关文件",
        "必要文件",
        "其他文件",
        "尚未确认",
        "后续确认",
        "不确定",
        "或许",
        "maybe",
        "perhaps",
        "to be checked",
    ],
)
def test_packet_rejects_unresolved_or_vague_plan_text(term: str) -> None:
    value = packet()
    value["phases"][0]["goal"] = f"实现: {term}"
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "PLAN_UNRESOLVED"


def test_packet_rejects_unresolved_terms_in_identifier_fields() -> None:
    value = packet()
    value["requirements"][0]["id"] = "TODO"
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "PLAN_UNRESOLVED"


@pytest.mark.parametrize(
    "certainty",
    [
        None,
        {},
        {"confirmed": False, "unresolved_items": [], "assumptions": []},
        {"confirmed": True, "unresolved_items": ["question"], "assumptions": []},
        {"confirmed": True, "unresolved_items": [], "assumptions": ["guess"]},
    ],
)
def test_packet_requires_exact_confirmed_certainty(certainty: object) -> None:
    value = packet()
    if certainty is None:
        del value["certainty"]
    else:
        value["certainty"] = certainty
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "PLAN_UNRESOLVED"


@pytest.mark.parametrize("scope", ["src/*.py", "src/**/test.py", "src/?", "src/[ab]"])
def test_packet_rejects_path_patterns_other_than_explicit_trees(scope: str) -> None:
    value = packet()
    value["phases"][0]["allowed_paths"] = [scope]
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "INVALID_PATH"


@pytest.mark.parametrize("scope", ["/src/app.py", "\\\\server\\share\\app.py"])
def test_packet_rejects_absolute_path_scopes_before_normalization(scope: str) -> None:
    value = packet()
    value["phases"][0]["allowed_paths"] = [scope]
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "INVALID_PATH"


@pytest.mark.parametrize("scope", ["C:relative", "D:relative", "C:/absolute", "C:\\absolute"])
def test_packet_rejects_windows_drive_qualified_paths(scope: str) -> None:
    value = packet()
    value["phases"][0]["allowed_paths"] = [scope]
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "INVALID_PATH"


def test_required_path_accepts_an_explicit_directory_tree() -> None:
    value = packet()
    value["acceptance"][0]["required_paths"] = ["src/**"]
    assert normalize_packet(value, available_checks={"pytest"})["acceptance"][0][
        "required_paths"
    ] == ["src/**"]


def test_final_phase_must_include_the_literal_union_of_earlier_paths() -> None:
    value = packet()
    value["requirements"].append({"id": "R2", "statement": "验证修改。", "acceptance_ids": ["A2"]})
    value["acceptance"].append(
        {
            "id": "A2",
            "criterion": "检查通过。",
            "verification": ["pytest"],
            "required_paths": ["tests/test_app.py"],
        }
    )
    value["phases"].append(
        {
            "id": "P2",
            "goal": "验证。",
            "requirement_ids": ["R2"],
            "acceptance_ids": ["A2"],
            "allowed_paths": ["tests/test_app.py"],
            "check_ids": ["pytest"],
        }
    )
    with pytest.raises(GuardError) as caught:
        normalize_packet(value, available_checks={"pytest"})
    assert caught.value.code == "REPAIR_SCOPE_INCOMPLETE"

    value["phases"][-1]["allowed_paths"].append("src/**")
    normalized = normalize_packet(value, available_checks={"pytest"})
    assert normalized["phases"][-1]["allowed_paths"] == ["tests/test_app.py", "src/**"]
