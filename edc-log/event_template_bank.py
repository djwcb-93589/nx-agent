from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Iterable, Any, Tuple
import hashlib
import re

import pandas as pd


@dataclass
class EventTemplateBank:
    """
    Group by eventTemplate, and keep up to k random content examples per template.
    Output container format: {template: [content1, content2, content3]}
    """
    k: int = 3
    seed: Optional[int] = 42
    bank: Dict[str, List[str]] = field(default_factory=dict)
    id_bank: Dict[str, str] = field(default_factory=dict)

    # ---------- Constructors ----------
    @classmethod
    def from_csv(
        cls,
        path: str,
        k: int = 3,
        seed: Optional[int] = 42,
        *,
        encoding: Optional[str] = None,
        mode: str = "auto",   # "auto" / "audit" / "auth"
        dedup_content: bool = False,
    ) -> "EventTemplateBank":
        df = pd.read_csv(path, encoding=encoding)
        return cls.from_df(df, k=k, seed=seed, dedup_content=dedup_content, mode=mode)

    @classmethod
    def from_df(
        cls,
        df: pd.DataFrame,
        k: int = 3,
        seed: Optional[int] = 42,
        *,
        dedup_content: bool = False,
        mode: str = "auto",   # "auto" / "audit" / "auth"
    ) -> "EventTemplateBank":
        mode = (mode or "auto").lower()

        cols = cls._resolve_columns(df, mode=mode)
        detected_mode = cols["mode"]
        group_col = "eventTemplate"
        group_sort = True

        if detected_mode == "audit":
            type_col, tpl_col, cnt_col, eid_col = cols["type"], cols["eventtemplate"], cols["content"], cols["eventid"]  # ✅ CHANGE

            work = df[[type_col, tpl_col, cnt_col, eid_col]].rename(  # ✅ CHANGE
                columns={type_col: "type", tpl_col: "eventTemplate", cnt_col: "content", eid_col: "eventId"}  # ✅ CHANGE
            ).copy()

            work["type"] = work["type"].astype("string").fillna("")
            work["eventTemplate"] = work["eventTemplate"].astype("string").fillna("")
            work["content"] = work["content"].astype("string")
            work["eventId"] = work["eventId"].astype("string").fillna("")

            # drop NaN/empty content
            work = work.dropna(subset=["content"])
            work["content"] = work["content"].astype(str)
            work = work[work["content"].str.strip() != ""]

            # template key: type + template
            work["eventTemplate"] = work["type"].astype(str).str.strip() + ": " + work["eventTemplate"].astype(str)

            # samples: type + content
            work["content_with_ctx"] = work["type"].astype(str).str.strip() + ": " + work["content"].astype(str)

        elif detected_mode == "auth":
            comp_col, proto_col, tpl_col, cnt_col, eid_col = cols["component"], cols["proto"], cols["eventtemplate"], cols["content"], cols["eventid"]  # ✅ CHANGE

            work = df[[comp_col, proto_col, tpl_col, cnt_col, eid_col]].rename(  # ✅ CHANGE
                columns={comp_col: "component", proto_col: "proto", tpl_col: "eventTemplate", cnt_col: "content", eid_col: "eventId"}  # ✅ CHANGE
            ).copy()

            work["eventId"] = work["eventId"].astype("string").fillna("")  # ✅ ADD
            work["component"] = work["component"].astype("string").fillna("")
            work["proto"] = work["proto"].astype("string").fillna("")
            work["eventTemplate"] = work["eventTemplate"].astype("string").fillna("")
            work["content"] = work["content"].astype("string")

            # drop NaN/empty content
            work = work.dropna(subset=["content"])
            work["content"] = work["content"].astype(str)
            work = work[work["content"].str.strip() != ""]

            # proto_norm: replace [...] -> [<*>] ONLY for template key
            proto_norm = work["proto"].astype(str).apply(lambda s: re.sub(r"\[[^\]]*\]", "[<*>]", s))

            # template key: component + proto_norm + eventTemplate
            # e.g. "webserver CRON[<*>]: pam_unix(...) session opened for user <*> by <*>"
            work["eventTemplate"] = (
                work["component"].astype(str).str.strip()
                + " "
                + proto_norm.astype(str).str.strip()
                + ": "
                + work["eventTemplate"].astype(str).str.strip()
            )

            # samples: component + ORIGINAL proto + content (proto不替换)
            work["content_with_ctx"] = (
                work["component"].astype(str).str.strip()
                + " "
                + work["proto"].astype(str).str.strip()
                + ": "
                + work["content"].astype(str)
            )

            # auth: merge rows by eventId (eventId <-> eventTemplate), preserve CSV order
            work["eventId"] = work["eventId"].astype(str).str.strip()
            work["_group_key"] = work["eventId"]
            missing_eid = work["_group_key"] == ""
            if missing_eid.any():
                # fallback for empty eventId rows, avoid dropping data
                work.loc[missing_eid, "_group_key"] = "__tpl__" + work.loc[missing_eid, "eventTemplate"]
            group_col = "_group_key"
            group_sort = False
        elif detected_mode == "dns":
            comp_col, tpl_col, cnt_col, eid_col = cols["component"], cols["eventtemplate"], cols["content"], cols["eventid"]  # ✅ CHANGE

            work = df[[comp_col, tpl_col, cnt_col, eid_col]].rename(  # ✅ CHANGE
                columns={comp_col: "component", tpl_col: "eventTemplate", cnt_col: "content", eid_col: "eventId"}  # ✅ CHANGE
            ).copy()

            work["eventId"] = work["eventId"].astype("string").fillna("")  # ✅ ADD
            work["component"] = work["component"].astype("string").fillna("")
            work["eventTemplate"] = work["eventTemplate"].astype("string").fillna("")
            work["content"] = work["content"].astype("string")

            # drop NaN/empty content（保持原逻辑）
            work = work.dropna(subset=["content"])
            work["content"] = work["content"].astype(str)
            work = work[work["content"].str.strip() != ""]

            # ✅ component_norm：把 [] 里的内容替换成 [<*>]（仅用于模板 key）
            # 例：dnsmasq[14522] -> dnsmasq[<*>]
            comp_norm = work["component"].astype(str).apply(lambda s: re.sub(r"\[[^\]]*\]", "[<*>]", s))

            # ✅ template key：component_norm + ": " + eventTemplate
            # 例：dnsmasq[<*>]: query[A] <*> from <*>
            work["eventTemplate"] = (
                comp_norm.astype(str).str.strip()
                + ": "
                + work["eventTemplate"].astype(str).str.strip()
            )

            # ✅ samples：component 原样 + ": " + content（component 不做替换）
            # 例：dnsmasq[14522]: query[A] xxx from 10.35.33.111
            work["content_with_ctx"] = (
                work["component"].astype(str).str.strip()
                + ": "
                + work["content"].astype(str)
            )
        elif detected_mode == "syslog":
            comp_col, proto_col, tpl_col, cnt_col, eid_col = (
                cols["component"], cols["proto"], cols["eventtemplate"], cols["content"], cols["eventid"]  # ✅ CHANGE
            )

            work = df[[comp_col, proto_col, tpl_col, cnt_col, eid_col]].rename(  # ✅ CHANGE
                columns={comp_col: "component", proto_col: "proto", tpl_col: "eventTemplate", cnt_col: "content", eid_col: "eventId"}  # ✅ CHANGE
            ).copy()

            work["eventId"] = work["eventId"].astype("string").fillna("")  # ✅ ADD
            work["component"] = work["component"].astype("string").fillna("")
            work["proto"] = work["proto"].astype("string").fillna("")
            work["eventTemplate"] = work["eventTemplate"].astype("string").fillna("")
            work["content"] = work["content"].astype("string")

            # drop NaN/empty content（保持原逻辑）
            work = work.dropna(subset=["content"])
            work["content"] = work["content"].astype(str)
            work = work[work["content"].str.strip() != ""]

            # ✅ proto_norm：把 [] 里的内容替换成 [<*>]（仅用于模板 key）
            proto_norm = work["proto"].astype(str).apply(lambda s: re.sub(r"\[[^\]]*\]", "[<*>]", s))

            # ✅ template key：component + proto_norm + ": " + eventTemplate
            # 例：inet-firewall CRON[<*>]: (root) CMD ( ... )
            work["eventTemplate"] = (
                work["component"].astype(str).str.strip()
                + " "
                + proto_norm.astype(str).str.strip()
                + ": "
                + work["eventTemplate"].astype(str).str.strip()
            )

            # ✅ samples：component + 原 proto + ": " + content（proto 不替换）
            work["content_with_ctx"] = (
                work["component"].astype(str).str.strip()
                + " "
                + work["proto"].astype(str).str.strip()
                + ": "
                + work["content"].astype(str)
            )


        else:
            raise ValueError(f"Unknown mode: {detected_mode}")

        # eventTemplate 统一转字符串
        work["eventTemplate"] = work["eventTemplate"].astype(str)

        if dedup_content:
            # 保持原逻辑：按 eventTemplate + content 去重（不影响抽样稳定性）
            work = work.drop_duplicates(subset=[group_col, "content"])

        bank: Dict[str, List[str]] = {}
        id_bank: Dict[str, str] = {}  # ✅ ADD

        for _, g in work.groupby(group_col, sort=group_sort):
            tpl = str(g["eventTemplate"].iloc[0])
            sample_source = g["content_with_ctx"]
            if detected_mode == "auth":
                # auth: pick up to k unique content samples for each merged eventId
                sample_source = sample_source.drop_duplicates()
            n = min(k, len(sample_source))
            seed_key = tpl if group_col == "eventTemplate" else f"{tpl}::{str(g['eventId'].iloc[0])}"
            rs = None if seed is None else cls._stable_seed(seed_key, seed)
            samples = sample_source.sample(n=n, random_state=rs).tolist()
            bank[tpl] = samples

            # ✅ ADD: 同一 template 下 eventId 一致，取第一个即可
            id_bank[tpl] = str(g["eventId"].iloc[0]) if "eventId" in g.columns else ""

        return cls(k=k, seed=seed, bank=bank, id_bank=id_bank)  # ✅ CHANGE


    # ---------- Public helpers ----------
    def to_dict(self) -> Dict[str, List[str]]:
        return dict(self.bank)

    def to_list(self) -> List[Dict[str, Any]]:
        """[{"eventTemplate": tpl, "samples": [...]}, ...]"""
        return [{"eventTemplate": t, "samples": s} for t, s in self.bank.items()]

    def to_prompt_blocks(self) -> List[str]:
        """["Template: ...\\nSamples:\\n- ...", ...]"""
        blocks = []
        for tpl, samples in self.bank.items():
            blocks.append("Template: " + tpl + "\nSamples:\n- " + "\n- ".join(samples))
        return blocks

    def items(self) -> Iterable[Tuple[str, List[str]]]:
        return self.bank.items()

    def __len__(self) -> int:
        return len(self.bank)

    def __getitem__(self, template: str) -> List[str]:
        return self.bank[template]

    # ---------- Internals ----------
    @staticmethod
    def _resolve_columns(df: pd.DataFrame, mode: str = "auto") -> Dict[str, str]:
        lower_map = {c.lower(): c for c in df.columns}
        eid_col = lower_map.get("eventid")

        has_auth   = all(k in lower_map for k in ["component", "proto", "eventtemplate", "content", "eventid"])  # ✅ CHANGE
        has_syslog = all(k in lower_map for k in ["component", "proto", "eventtemplate", "content", "eventid"])  # ✅ CHANGE
        has_dns    = all(k in lower_map for k in ["component", "eventtemplate", "content", "eventid"])          # ✅ CHANGE
        has_audit  = all(k in lower_map for k in ["type", "eventtemplate", "content", "eventid"])               # ✅ CHANGE


        if mode == "auto":
            # auth 和 syslog 列集合一致；如果你想区分，建议调用时显式 mode="syslog"
            if has_auth:
                mode = "auth"
            elif has_syslog:
                mode = "syslog"
            elif has_dns:
                mode = "dns"
            elif has_audit:
                mode = "audit"
            else:
                raise ValueError(f"Cannot auto-detect mode. Columns: {list(df.columns)}")

        if mode == "auth":
            if not has_auth:
                raise ValueError(f"Missing required columns for auth: Component/Proto/EventTemplate/Content. Columns: {list(df.columns)}")
            return {
                "mode": "auth",
                "component": lower_map["component"],
                "proto": lower_map["proto"],
                "eventtemplate": lower_map["eventtemplate"],
                "content": lower_map["content"],
                "eventid": lower_map["eventid"],
            }

        if mode == "dns":
            if not has_dns:
                raise ValueError(f"Missing required columns for dns: Component/EventTemplate/Content. Columns: {list(df.columns)}")
            return {
                "mode": "dns",
                "component": lower_map["component"],
                "eventtemplate": lower_map["eventtemplate"],
                "content": lower_map["content"],
                "eventid": lower_map["eventid"],
            }

        if mode == "audit":
            if not has_audit:
                raise ValueError(f"Missing required columns for audit: Type/EventTemplate/Content. Columns: {list(df.columns)}")
            return {
                "mode": "audit",
                "type": lower_map["type"],
                "eventtemplate": lower_map["eventtemplate"],
                "content": lower_map["content"],
                "eventid": lower_map["eventid"],
            }
        
        if mode == "syslog":
            if not has_syslog:
                raise ValueError(f"Missing required columns for syslog: Component/Proto/EventTemplate/Content. Columns: {list(df.columns)}")
            return {
                "mode": "syslog",
                "component": lower_map["component"],
                "proto": lower_map["proto"],
                "eventtemplate": lower_map["eventtemplate"],
                "content": lower_map["content"],
                "eventid": lower_map["eventid"],
            }

        raise ValueError(f"Unknown mode: {mode}")


    @staticmethod
    def _stable_seed(template: str, seed: int) -> int:
        """
        Make per-template deterministic random_state across machines/runs:
        random_state = stable_hash(template + seed) -> 32-bit int
        """
        s = f"{seed}::{template}".encode("utf-8")
        h = hashlib.md5(s).hexdigest()[:8]  # 32-bit
        return int(h, 16)

    def to_prompt_blocks_with_eventids(self) -> List[List[Any]]:
        blocks: List[str] = []
        ids: List[str] = []
        for tpl, samples in self.bank.items():
            blocks.append("Template: " + tpl + "\nSamples:\n- " + "\n- ".join(samples))
            ids.append(self.id_bank.get(tpl, ""))
        return [blocks, ids]


if __name__ == "__main__":
    # auth 示例（你上传的文件）
    bank = EventTemplateBank.from_csv("/mnt/data/auth.log_structured.csv", k=3, seed=42, mode="auth")
    print("Num templates:", len(bank))
    print(bank.to_prompt_blocks()[:2])
