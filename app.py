"""Traffic Filter Agent — Interactive chat UI with streaming and file upload.

Streamlit app that exposes the Wireshark-MCP ReAct agent through a chat
interface with separate display areas for thinking, tool execution, and
final responses.

Usage:
    streamlit run app.py
"""

from __future__ import annotations

import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

import streamlit as st

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Traffic Filter Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS tweaks — distinguish thinking / tool / response blocks
# ---------------------------------------------------------------------------
st.markdown(
    """<style>
    .thinking-block { border-left: 3px solid #f0ad4e; padding-left: 12px; color: #b08d3c; font-style: italic; margin: 8px 0; }
    .tool-block { border-left: 3px solid #5bc0de; padding-left: 12px; color: #3a7d8c; font-family: monospace; margin: 8px 0; }
    .response-block { border-left: 3px solid #5cb85c; padding-left: 12px; margin: 8px 0; }
    .error-block { border-left: 3px solid #d9534f; padding-left: 12px; color: #a94442; margin: 8px 0; }
    </style>""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar — file upload
# ---------------------------------------------------------------------------
st.sidebar.header("📁 PCAP 文件上传")

uploaded_file = st.sidebar.file_uploader(
    "选择 .pcap / .pcapng 文件",
    type=["pcap", "pcapng"],
    help="上传后文件路径会自动注入到对话中",
)

UPLOAD_DIR = Path(tempfile.gettempdir()) / "traffic_filter_agent"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

if uploaded_file is not None:
    dest = UPLOAD_DIR / uploaded_file.name
    with open(dest, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.session_state.last_pcap_path = str(dest)
    st.sidebar.success(f"✅ 已就绪: `{dest}`")
    if st.sidebar.button("清除上传文件"):
        dest.unlink(missing_ok=True)
        st.session_state.last_pcap_path = None
        st.sidebar.info("已清除")
        st.rerun()
else:
    st.sidebar.info("请上传 PCAP 文件以开始分析")

# Quick presets
st.sidebar.divider()
st.sidebar.header("⚡ 快捷操作")
if st.sidebar.button("运行全自动分析流水线"):
    if "last_pcap_path" not in st.session_state:
        st.sidebar.warning("请先上传 PCAP 文件")
    else:
        st.session_state["pending_prompt"] = (
            f"请对 {st.session_state['last_pcap_path']} 运行全自动分析流水线，"
            "生成完整的中文安全审计报告。"
        )
        st.rerun()

# ---------------------------------------------------------------------------
# Session state init
# ---------------------------------------------------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = []  # list of dicts: role, content, thinking, tools, error

if "thread_id" not in st.session_state:
    st.session_state.thread_id = str(uuid.uuid4())[:8]

if "agent" not in st.session_state:
    # Lazy init to avoid paying the MCP startup cost on every rerun
    st.session_state.agent = None

if "last_pcap_path" not in st.session_state:
    st.session_state.last_pcap_path = None


def _get_or_create_agent():
    """Build the ReAct agent once per session (cached in st.session_state)."""
    if st.session_state.agent is None:
        from src.agent import _get_agent_graph

        with st.spinner("正在初始化 Wireshark-MCP 服务和 AI 模型…"):
            st.session_state.agent = _get_agent_graph()
    return st.session_state.agent


def _render_message(msg: Dict[str, Any]):
    """Render a single chat message with optional thinking / tool / error blocks."""
    role = msg["role"]
    with st.chat_message(role):
        if msg.get("error"):
            st.markdown(
                f'<div class="error-block">{msg["error"]}</div>',
                unsafe_allow_html=True,
            )

        if msg.get("tools"):
            with st.expander("🔧 工具执行详情", expanded=False):
                st.markdown(
                    f'<div class="tool-block">{msg["tools"]}</div>',
                    unsafe_allow_html=True,
                )

        if msg.get("thinking"):
            with st.expander("🤔 思考过程", expanded=False):
                st.markdown(
                    f'<div class="thinking-block">{msg["thinking"]}</div>',
                    unsafe_allow_html=True,
                )

        if msg.get("content"):
            st.markdown(msg["content"])


# ---------------------------------------------------------------------------
# Render message history
# ---------------------------------------------------------------------------
st.title("🔍 Traffic Filter Agent")
st.caption("基于 Wireshark-MCP 的交互式网络流量安全分析")

for msg in st.session_state.messages:
    _render_message(msg)

# ---------------------------------------------------------------------------
# Handle pending prompt (triggered from sidebar quick actions)
# ---------------------------------------------------------------------------
if "pending_prompt" in st.session_state:
    prompt = st.session_state.pop("pending_prompt")
else:
    prompt = st.chat_input("输入分析指令，或上传 PCAP 文件后点击快捷操作…")

if not prompt:
    st.stop()

# ---------------------------------------------------------------------------
# Process user input
# ---------------------------------------------------------------------------

# Inject PCAP path if available
pcap_path = None
if "last_pcap_path" in st.session_state and st.session_state.last_pcap_path:
    pcap_path = st.session_state.last_pcap_path
    # If the user hasn't mentioned a specific file path, prepend system context
    if pcap_path not in prompt:
        prompt = f"[PCAP 文件路径: {pcap_path}]\n\n{prompt}"

# Add user message
st.session_state.messages.append({"role": "user", "content": prompt})
with st.chat_message("user"):
    st.markdown(prompt)

# ---------------------------------------------------------------------------
# Run agent with streaming
# ---------------------------------------------------------------------------
agent = _get_or_create_agent()

with st.chat_message("assistant"):
    # --- placeholders for the three output channels ---
    thinking_placeholder = st.empty()
    tools_placeholder = st.empty()
    response_placeholder = st.empty()

    # Mutable state container (avoid nonlocal across scope boundaries)
    state: Dict[str, Any] = {
        "thinking_text": "",
        "tools_parts": [],
        "response_text": "",
        "tool_count": 0,
        "tool_finished": 0,
        "msg_has_tool_calls": False,
    }

    async def _stream():
        from langchain_core.messages import HumanMessage

        config = {"configurable": {"thread_id": st.session_state.thread_id}}
        tool_names: Dict[str, str] = {}

        try:
            async for event in agent.astream_events(
                {"messages": [HumanMessage(content=prompt)]},
                config=config,
                version="v2",
            ):
                kind = event["event"]

                # ------ LLM token stream ------
                if kind == "on_chat_model_stream":
                    chunk = event["data"]["chunk"]
                    content = getattr(chunk, "content", "") or ""
                    tc_chunks = getattr(chunk, "tool_call_chunks", None) or []

                    if tc_chunks:
                        state["msg_has_tool_calls"] = True

                    if content:
                        if state["msg_has_tool_calls"] or state["tool_count"] > 0:
                            state["thinking_text"] += content
                            thinking_placeholder.markdown(
                                f'<div class="thinking-block">🤔 {state["thinking_text"]}</div>',
                                unsafe_allow_html=True,
                            )
                        else:
                            state["response_text"] += content
                            response_placeholder.markdown(state["response_text"])

                # ------ Tool start ------
                elif kind == "on_tool_start":
                    state["tool_count"] += 1
                    state["msg_has_tool_calls"] = False
                    name = event["name"]
                    run_id = event["run_id"]
                    tool_names[run_id] = name

                    inp = event["data"].get("input", {})
                    inp_str = str(inp)
                    if len(inp_str) > 300:
                        inp_str = inp_str[:300] + "…"

                    state["tools_parts"].append(f"▶ **{name}**\n```\n{inp_str}\n```")
                    tools_placeholder.markdown(
                        "🔧 工具执行中…\n\n" + "\n\n".join(state["tools_parts"])
                    )

                # ------ Tool end ------
                elif kind == "on_tool_end":
                    state["tool_finished"] += 1
                    run_id = event["run_id"]
                    name = tool_names.get(run_id, event["name"])

                    out = event["data"].get("output", "")
                    out_str = str(out)
                    if len(out_str) > 600:
                        out_str = out_str[:600] + "…"

                    for i in range(len(state["tools_parts"]) - 1, -1, -1):
                        if state["tools_parts"][i].startswith(f"▶ **{name}**"):
                            state["tools_parts"][i] = (
                                f"✅ **{name}**\n```\n{out_str}\n```"
                            )
                            break

                    tools_placeholder.markdown(
                        "🔧 工具执行详情\n\n" + "\n\n".join(state["tools_parts"])
                    )

        except Exception as exc:
            st.error(f"分析过程出错: {exc}")
            raise

    # Run the async streaming loop
    try:
        asyncio.run(_stream())
    except Exception:
        pass

    # --- Final render after streaming completes ---
    thinking_placeholder.empty()
    tools_placeholder.empty()
    response_placeholder.empty()

    thinking_text = state["thinking_text"]
    tools_parts = state["tools_parts"]
    response_text = state["response_text"]
    tool_count = state["tool_count"]

    # If no tools were used, the thinking text is actually the response.
    if tool_count == 0 and thinking_text:
        response_text = thinking_text
        thinking_text = ""

    # Final response
    if response_text:
        st.markdown(response_text)
    elif not thinking_text and not tools_parts:
        st.info("分析完成，但未生成文本输出。请检查 MCP 服务是否正常运行。")

    # Thinking block
    if thinking_text:
        with st.expander("🤔 思考过程", expanded=False):
            st.markdown(
                f'<div class="thinking-block">{thinking_text}</div>',
                unsafe_allow_html=True,
            )

    # Tools block
    if tools_parts:
        with st.expander("🔧 工具执行详情", expanded=False):
            st.markdown(
                "\n\n".join(tools_parts), unsafe_allow_html=False,
            )

    # --- Record message ---
    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": response_text,
            "thinking": thinking_text,
            "tools": "\n\n".join(tools_parts) if tools_parts else "",
            "error": "",
        }
    )
