from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import hashlib
import re


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AIT_ROOT = PROJECT_ROOT / "AIT"
ARTIFACT_ROOT = PROJECT_ROOT / "artifacts"
FIELD_SEMANTICS_DIR = ARTIFACT_ROOT / "field_semantics"
SCHEMA_MAPPINGS_DIR = ARTIFACT_ROOT / "schema_mappings"
MAPPED_PAIRS_DIR = ARTIFACT_ROOT / "mapped_pairs"
PARAMS_DIR = ARTIFACT_ROOT / "params"
GRAPH_SOURCES_DIR = ARTIFACT_ROOT / "graphs" / "sources"
GRAPH_FUSED_DIR = ARTIFACT_ROOT / "graphs" / "fused"


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    family: str
    csv_path: Path
    tag: str
    poi_schema_path: Path
    relation_csv_path: Path
    params_output_path: Path
    extractor_script_path: Path
    log_source: str
    extractor_extra_args: tuple[str, ...] = ()

    @property
    def template2samples_path(self) -> Path:
        return self.csv_path.with_name("template2samples.json")

    @property
    def pairs_path(self) -> Path:
        return FIELD_SEMANTICS_DIR / f"pairs_{self.tag}.json"

    @property
    def schema_path(self) -> Path:
        return SCHEMA_MAPPINGS_DIR / f"schema_{self.tag}.json"

    @property
    def mapped_pairs_path(self) -> Path:
        return MAPPED_PAIRS_DIR / f"pairs_{self.tag}_mapped.json"

    def with_project_root(self, project_root: Path) -> "DatasetSpec":
        root = project_root.resolve()
        old_root = PROJECT_ROOT.resolve()

        def rebase(path: Path) -> Path:
            resolved = path.resolve()
            try:
                return root / resolved.relative_to(old_root)
            except ValueError:
                return resolved

        return replace(
            self,
            csv_path=rebase(self.csv_path),
            poi_schema_path=rebase(self.poi_schema_path),
            relation_csv_path=rebase(self.relation_csv_path),
            params_output_path=rebase(self.params_output_path),
            extractor_script_path=rebase(self.extractor_script_path),
        )


@dataclass(frozen=True)
class DatasetPattern:
    path_fragment: str
    name: str
    family: str
    poi_schema_path: Path
    relation_csv_path: Path
    params_output_path: Path
    extractor_script_path: Path
    log_source: str
    extractor_extra_args: tuple[str, ...] = ()


DATASET_PATTERNS: tuple[DatasetPattern, ...] = (
    DatasetPattern(
        path_fragment="internal_share/logs/audit_internal_share/audit_internal_share/3.csv",
        name="internal_share_audit",
        family="audit",
        poi_schema_path=PROJECT_ROOT / "schemas" / "audit_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "audit_relation.csv",
        params_output_path=PARAMS_DIR / "internal_share_audit_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_internal_share_audit3_params_deepseek.py",
        log_source="audit",
    ),
    DatasetPattern(
        path_fragment="intranet_server/logs/audit_internal_server/audit_internal_server/3.csv",
        name="intranet_server_audit",
        family="audit",
        poi_schema_path=PROJECT_ROOT / "schemas" / "audit_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "audit_relation.csv",
        params_output_path=PARAMS_DIR / "intranet_server_audit_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_intranet_server_audit3_params_deepseek.py",
        log_source="audit",
    ),
    DatasetPattern(
        path_fragment="intranet_server/logs/auth/3.csv",
        name="intranet_server_auth",
        family="auth",
        poi_schema_path=PROJECT_ROOT / "schemas" / "auth_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "auth_relation.csv",
        params_output_path=PARAMS_DIR / "intranet_server_auth_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_intranet_server_auth3_params_deepseek.py",
        log_source="auth",
    ),
    DatasetPattern(
        path_fragment="inet-firewall/logs-label/dnsmasq/3.csv",
        name="inet_firewall_dns",
        family="dns",
        poi_schema_path=PROJECT_ROOT / "schemas" / "dns_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "dns_relation.csv",
        params_output_path=PARAMS_DIR / "inet_firewall_dnsmasq_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_inet_firewall_dns3_params_fast.py",
        log_source="dns",
    ),
    DatasetPattern(
        path_fragment="firewallexample/设备管理日志：管理登录&退出日志（webui）/3.csv",
        name="firewall_example_2_1_1_1",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_2_1_1_1_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="firewallexample/设备管理日志：管理登录&退出日志 (CLI)/3.csv",
        name="firewall_example_2_1_2_1",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_2_1_2_1_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="firewallexample/防火墙安全策略日志/3.csv",
        name="firewall_example_2_5_1",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_2_5_1_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="firewallexample/设备管理日志：安全域创建&编辑/3.csv",
        name="firewall_example_2_5_6",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_2_5_6_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="firewallexample/设备管理日志：添加&显示&删除&开机恢复黑名单/3.csv",
        name="firewall_example_2_5_7",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_2_5_7_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="firewallexample/customer_event_simulated/3.csv",
        name="firewall_example_customer_event_simulated",
        family="firewall",
        poi_schema_path=PROJECT_ROOT / "schemas" / "firewall_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "firewall_relation.csv",
        params_output_path=PARAMS_DIR / "firewall_example_customer_event_simulated_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_firewall_example_params.py",
        log_source="firewall",
    ),
    DatasetPattern(
        path_fragment="vpn/logs/openvpn/3.csv",
        name="vpn_openvpn",
        family="vpn",
        poi_schema_path=PROJECT_ROOT / "schemas" / "vpn_POI v2.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "vpn_relation_aligned_final.csv",
        params_output_path=PARAMS_DIR / "vpn_openvpn_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_vpn_openvpn_3_params_deepseek.py",
        log_source="vpn",
    ),
    DatasetPattern(
        path_fragment="intranet_server/logs/apache2/intranet.price.fox.org-access/3.csv",
        name="apache_access",
        family="apache",
        poi_schema_path=PROJECT_ROOT / "schemas" / "apache_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "apache_relation.csv",
        params_output_path=PARAMS_DIR / "intranet_server_apache_price_fox_org_access_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_intranet_server_apache_access3_params.py",
        log_source="apache",
        extractor_extra_args=("--default-host", "intranet.price.fox.org", "--default-program", "apache"),
    ),
    DatasetPattern(
        path_fragment="intranet_server/logs/apache2/intranet.price.fox.org-error/3.csv",
        name="apache_error",
        family="apache",
        poi_schema_path=PROJECT_ROOT / "schemas" / "apache_POI.csv",
        relation_csv_path=PROJECT_ROOT / "schemas" / "apache_relation.csv",
        params_output_path=PARAMS_DIR / "intranet_server_apache_price_fox_org_error_3_params_extracted.csv",
        extractor_script_path=PROJECT_ROOT / "extract_intranet_server_apache_error3_params.py",
        log_source="apache",
        extractor_extra_args=("--default-host", "intranet.price.fox.org"),
    ),
)


def build_ait_output_tag(csv_path: Path, ait_root: Path = AIT_ROOT) -> str:
    relative_path = csv_path.resolve().relative_to(ait_root.resolve()).with_suffix("")
    parts = []
    for part in relative_path.parts:
        normalized = re.sub(r"[^0-9A-Za-z]+", "_", part).strip("_")
        if not normalized:
            normalized = "u_" + hashlib.sha1(part.encode("utf-8")).hexdigest()[:10]
        parts.append(normalized)
    return "_".join(part for part in parts if part) or "ait"


def spec_for_csv(csv_path: Path, ait_root: Path = AIT_ROOT) -> DatasetSpec | None:
    csv_path = csv_path.resolve()
    relative = csv_path.relative_to(ait_root.resolve()).as_posix()
    canonical_relative = relative.replace("firewallexamplae/", "firewallexample/", 1)
    for pattern in DATASET_PATTERNS:
        if canonical_relative == pattern.path_fragment:
            return DatasetSpec(
                name=pattern.name,
                family=pattern.family,
                csv_path=csv_path,
                tag=build_ait_output_tag(csv_path, ait_root),
                poi_schema_path=pattern.poi_schema_path.resolve(),
                relation_csv_path=pattern.relation_csv_path.resolve(),
                params_output_path=pattern.params_output_path.resolve(),
                extractor_script_path=pattern.extractor_script_path.resolve(),
                log_source=pattern.log_source,
                extractor_extra_args=pattern.extractor_extra_args,
            )
    return None


def discover_dataset_specs(ait_root: Path = AIT_ROOT) -> list[DatasetSpec]:
    ait_root = ait_root.resolve()
    specs_by_name: dict[str, DatasetSpec] = {}
    for csv_path in sorted(ait_root.rglob("3.csv")):
        spec = spec_for_csv(csv_path, ait_root)
        if spec is not None:
            existing = specs_by_name.get(spec.name)
            if existing is None or "firewallexamplae" in existing.csv_path.as_posix():
                specs_by_name[spec.name] = spec
    return sorted(specs_by_name.values(), key=lambda item: item.name)
