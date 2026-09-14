"""
dashboard.py — Telegram Cyber Threat Intelligence Dashboard
Run: streamlit run dashboard.py
"""

import streamlit as st
import json
import os
import pandas as pd
from datetime import datetime
from collections import Counter
import plotly.express as px
import plotly.graph_objects as go

# ── Config ─────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
)

DATA_FILE = os.path.join("data", "output.json")

RISK_COLORS = {
    "CRITICAL": "#ff3c3c",
    "HIGH":     "#ff8600",
    "MEDIUM":   "#ffd166",
    "LOW":      "#39ff14",
}

THREAT_ICONS = {
    "DataBreach": "🗄️", "Ransomware": "🔒", "DDoS": "💥",
    "Defacement": "🖥️", "Malware": "🦠", "Exploit": "⚡",
    "PhishingKit": "🎣", "CredentialLeak": "🔑", "Hacktivism": "✊",
    "ThreatActor": "👤", "Noise": "📢", "Unknown": "❓", "Other": "📌",
}

# ── Load data ──────────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_data():
    if not os.path.exists(DATA_FILE):
        return pd.DataFrame()
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            records = json.load(f)
        if not records:
            return pd.DataFrame()
        df = pd.DataFrame(records)
        df["timestamp"]  = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df["collected_at"] = pd.to_datetime(df["collected_at"], errors="coerce")
        df["risk_score"] = pd.to_numeric(df.get("risk_score", 0), errors="coerce").fillna(0)
        df["date"]       = df["timestamp"].dt.date
        return df
    except Exception as e:
        st.error(f"Failed to load data: {e}")
        return pd.DataFrame()

df = load_data()

# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR — Filters
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.title("🛡️ Threat Intel")

    if st.button("🔄 Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.subheader("Filters")

    selected_risk = selected_channels = selected_threats = []
    date_range = keyword_search = None

    if not df.empty:
        all_risks    = [r for r in ["CRITICAL","HIGH","MEDIUM","LOW"] if r in df["risk_level"].values]
        all_channels = sorted(df["channel_name"].dropna().unique())
        all_threats  = sorted(df["threat_type"].dropna().unique()) if "threat_type" in df.columns else []

        selected_risk     = st.multiselect("Risk Level",    all_risks,    default=all_risks)
        selected_channels = st.multiselect("Channel",       all_channels, default=all_channels)
        selected_threats  = st.multiselect("Threat Type",   all_threats,  default=all_threats)
        keyword_search    = st.text_input("🔍 Keyword search", placeholder="ransomware, India…")

        if "date" in df.columns:
            date_range = st.date_input("Date Range", value=(df["date"].min(), df["date"].max()))

    st.divider()
    st.caption(f"File: `{DATA_FILE}`")
    st.caption(f"Loaded: {datetime.now().strftime('%H:%M:%S')}")

# ══════════════════════════════════════════════════════════════════════════════
# APPLY FILTERS
# ══════════════════════════════════════════════════════════════════════════════
if df.empty:
    st.warning("⚠️ No data found. Run the bot first: `python -m app.main`")
    st.stop()

filtered = df.copy()
if selected_risk:     filtered = filtered[filtered["risk_level"].isin(selected_risk)]
if selected_channels: filtered = filtered[filtered["channel_name"].isin(selected_channels)]
if selected_threats and "threat_type" in filtered.columns:
    filtered = filtered[filtered["threat_type"].isin(selected_threats)]
if date_range and len(date_range) == 2:
    filtered = filtered[(filtered["date"] >= date_range[0]) & (filtered["date"] <= date_range[1])]
if keyword_search:
    mask = filtered.apply(
        lambda r: any(keyword_search.lower() in str(r.get(f, "")).lower()
                      for f in ["message_text", "exact_keywords", "summary"]),
        axis=1
    )
    filtered = filtered[mask]

# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.title("🛡️ Cyber Threat Intelligence Dashboard")
st.caption("Telegram channel monitoring · LangChain + Gemini · Auto-refreshes every 30s")
st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 1 — KPI METRICS
# ══════════════════════════════════════════════════════════════════════════════
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Total",    len(filtered))
c2.metric("🔴 Critical", len(filtered[filtered["risk_level"] == "CRITICAL"]))
c3.metric("🟠 High",     len(filtered[filtered["risk_level"] == "HIGH"]))
c4.metric("🟡 Medium",   len(filtered[filtered["risk_level"] == "MEDIUM"]))
c5.metric("📡 Channels", filtered["channel_name"].nunique())
c6.metric("⚠️ Threats",  len(filtered[filtered.get("is_threat", pd.Series(False)) == True]) if "is_threat" in filtered.columns else "—")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 2 — 3 CHARTS
# ══════════════════════════════════════════════════════════════════════════════
col1, col2, col3 = st.columns(3)

# Chart 1 — Risk donut
with col1:
    st.subheader("Risk Levels")
    risk_counts = filtered["risk_level"].value_counts()
    fig = go.Figure(go.Pie(
        labels=risk_counts.index, values=risk_counts.values, hole=0.5,
        marker=dict(colors=[RISK_COLORS.get(r, "#888") for r in risk_counts.index]),
        textinfo="label+percent", textfont=dict(size=12),
    ))
    fig.update_layout(showlegend=False, margin=dict(t=0,b=0,l=0,r=0), height=240)
    st.plotly_chart(fig, use_container_width=True)

# Chart 2 — Threat types
with col2:
    st.subheader("Threat Types")
    if "threat_type" in filtered.columns:
        tt = filtered["threat_type"].value_counts().head(8)
        fig2 = go.Figure(go.Bar(
            x=tt.values, y=tt.index, orientation="h",
            marker_color="#00e5ff", text=tt.values, textposition="outside",
        ))
        fig2.update_layout(
            xaxis=dict(showticklabels=False), margin=dict(t=0,b=0,l=0,r=30), height=240
        )
        st.plotly_chart(fig2, use_container_width=True)

# Chart 3 — Per channel
with col3:
    st.subheader("Per Channel")
    ch = filtered["channel_name"].value_counts()
    fig3 = go.Figure(go.Bar(
        x=ch.values, y=ch.index, orientation="h",
        marker_color="#7c6cff", text=ch.values, textposition="outside",
    ))
    fig3.update_layout(
        xaxis=dict(showticklabels=False), margin=dict(t=0,b=0,l=0,r=30), height=240
    )
    st.plotly_chart(fig3, use_container_width=True)

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 3 — Timeline + Top Keywords
# ══════════════════════════════════════════════════════════════════════════════
tcol, kcol = st.columns([2, 1])

with tcol:
    st.subheader("Activity Timeline")
    if "date" in filtered.columns:
        tl = filtered.groupby(["date","risk_level"]).size().reset_index(name="count")
        fig4 = px.bar(tl, x="date", y="count", color="risk_level",
                      color_discrete_map=RISK_COLORS, barmode="stack")
        fig4.update_layout(margin=dict(t=0,b=0,l=0,r=0), height=220,
                           legend_title="Risk", xaxis_title="", yaxis_title="Messages")
        st.plotly_chart(fig4, use_container_width=True)

with kcol:
    st.subheader("Top Keywords")
    if "exact_keywords" in filtered.columns:
        all_kws = []
        for kws in filtered["exact_keywords"].dropna():
            if isinstance(kws, list): all_kws.extend(kws)
            elif isinstance(kws, str):
                try: all_kws.extend(json.loads(kws))
                except: pass
        if all_kws:
            kw_df = pd.DataFrame(Counter(all_kws).most_common(8), columns=["Keyword","Count"])
            fig5 = go.Figure(go.Bar(
                x=kw_df["Count"], y=kw_df["Keyword"], orientation="h",
                marker_color="#ff8600", text=kw_df["Count"], textposition="outside",
            ))
            fig5.update_layout(
                xaxis=dict(showticklabels=False), margin=dict(t=0,b=0,l=0,r=30), height=220
            )
            st.plotly_chart(fig5, use_container_width=True)

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 4 — Language breakdown
# ══════════════════════════════════════════════════════════════════════════════
if "original_language" in filtered.columns:
    lang_counts = filtered["original_language"].value_counts()
    if len(lang_counts) > 1:
        st.subheader("🌐 Languages Detected")
        lcols = st.columns(min(len(lang_counts), 6))
        for i, (lang, cnt) in enumerate(lang_counts.items()):
            if i < 6:
                lcols[i].metric(lang, cnt, f"{round(cnt/len(filtered)*100)}%")
        st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 5 — Threat Feed + Record Inspector
# ══════════════════════════════════════════════════════════════════════════════
st.subheader("🚨 Threat Feed")
feed_col, detail_col = st.columns([1.2, 1])

with feed_col:
    feed_df = filtered.sort_values(
        "risk_score" if "risk_score" in filtered.columns else "timestamp",
        ascending=False
    ).head(50)

    for _, row in feed_df.iterrows():
        risk        = str(row.get("risk_level", "LOW"))
        threat_type = str(row.get("threat_type", "Unknown"))
        channel     = str(row.get("channel_name", "?"))
        ts          = str(row.get("timestamp", ""))[:16]
        summary     = str(row.get("summary", row.get("message_text", "")))[:180]
        score       = row.get("risk_score", 0)
        lang        = row.get("original_language", "")
        icon        = THREAT_ICONS.get(threat_type, "📌")

        keywords = row.get("exact_keywords", [])
        if isinstance(keywords, str):
            try: keywords = json.loads(keywords)
            except: keywords = []

        color = RISK_COLORS.get(risk, "#888")
        kw_tags = " · ".join((keywords or [])[:5])

        st.markdown(
            f"""<div style="border-left:4px solid {color};background:#0f1628;
            padding:14px 18px;margin-bottom:10px;border-radius:4px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <span style="font-weight:600;color:#e0eeff;">{icon} {threat_type}</span>
                <span style="color:{color};font-size:12px;font-weight:bold;">{risk} · {score}</span>
            </div>
            <div style="font-size:12px;color:#4a7a9b;margin-bottom:6px;">
                📡 {channel} &nbsp;·&nbsp; 🕐 {ts} &nbsp;·&nbsp; 🌐 {lang}
            </div>
            <div style="font-size:13px;color:#8ab4cc;line-height:1.5;">{summary}</div>
            {"<div style='margin-top:6px;font-size:11px;color:#3a8a9a;'>🔑 " + kw_tags + "</div>" if kw_tags else ""}
            </div>""",
            unsafe_allow_html=True
        )

with detail_col:
    st.subheader("🔎 Record Inspector")

    if not filtered.empty:
        options = filtered.apply(
            lambda r: f"[{r.get('risk_level','?')}] {r.get('channel_name','?')} — #{r.get('message_id','?')}",
            axis=1
        ).tolist()

        idx = st.selectbox("Pick a record", range(len(options)), format_func=lambda i: options[i])
        row = filtered.iloc[idx]

        st.markdown(f"**Channel:** {row.get('channel_name','—')}")
        st.markdown(f"**Time:** {str(row.get('timestamp',''))[:19]}")
        st.markdown(f"**Language:** {row.get('original_language','—')} `{row.get('language_code','??')}`")
        st.markdown(f"**Risk:** `{row.get('risk_level','—')}` (score: {row.get('risk_score',0)})")
        st.markdown(f"**Type:** {row.get('threat_type','—')}")
        st.markdown(f"**Confidence:** {round(float(row.get('classification_confidence',0) or 0)*100)}%")
        st.markdown(f"**Reason:** _{row.get('classification_reasoning','—')}_")

        st.markdown("**Summary:**")
        st.info(str(row.get("summary","—"))[:400])

        # Keywords
        kws = row.get("exact_keywords", [])
        if isinstance(kws, str):
            try: kws = json.loads(kws)
            except: kws = []
        if kws:
            st.markdown("**Matched Keywords:**")
            st.code(", ".join(kws))

        # Proximity / synonym matches
        prox = row.get("proximity_matches", [])
        if prox:
            st.markdown("**Proximity Matches:**")
            st.code(str(prox))

        syn = row.get("synonym_matches", [])
        if syn:
            st.markdown("**Synonym Matches:**")
            st.code(str(syn))

        # Entities
        entities = row.get("entities", {})
        if isinstance(entities, str):
            try: entities = json.loads(entities)
            except: entities = {}
        if entities:
            st.markdown("**Extracted Entities:**")
            for k, v in entities.items():
                if v:
                    st.markdown(f"- **{k}:** `{v}`")

        with st.expander("📄 Original Message"):
            st.text(str(row.get("message_text","—"))[:1000])

        if str(row.get("original_language","English")) != "English":
            with st.expander("🌐 Translated Text"):
                st.text(str(row.get("translated_text","—"))[:1000])

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
# ROW 6 — Raw Data Table
# ══════════════════════════════════════════════════════════════════════════════
with st.expander("📋 Raw Data Table"):
    show_cols = [c for c in [
        "timestamp","channel_name","risk_level","risk_score",
        "threat_type","original_language","is_threat",
        "classification_confidence","summary","exact_keywords"
    ] if c in filtered.columns]

    st.dataframe(
        filtered[show_cols].sort_values(
            "risk_score" if "risk_score" in filtered.columns else show_cols[0],
            ascending=False
        ),
        use_container_width=True, height=380,
    )

    st.download_button(
        "⬇️ Download CSV",
        data=filtered.to_csv(index=False),
        file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
        mime="text/csv",
    )

st.caption("Telegram Threat Intel Bot · LangChain + Gemini + Telethon")