import streamlit as st
import pandas as pd
import re
from typing import List
from datetime import datetime

# App config
st.set_page_config(
    page_title="Request ID & Log Extractor",
    layout="wide"
)

st.title("🧠 Request ID & Log Extractor")

# Utilities
predefined_patterns = {
                "UUID": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                "REQ-YYYY-MM-NNN": r"REQ-\d{4}-\d{2}-\d+",
                "Hex String (8+ chars)": r"\b[a-f0-9]{8,}\b",
                "RequestID": r"INFO\s*--\s*:\s\[(.*?)\]",
                "Custom Regex": ""
            }

timestamp_pattern = re.compile(
    r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6} #\d{7}]"
)

accepted_files = ["csv", "xlsx"]

def extract_request_ids(texts: List[str], pattern: str) -> List[str]:
    matches = []
    compiled = re.compile(pattern, re.IGNORECASE)

    for text in texts:
        found = compiled.findall(text)
        if found:
            matches.extend(found)

    return sorted(set(matches))

def read_uploaded_file(uploaded_file: st.runtime.uploaded_file_manager.UploadedFile) -> pd.DataFrame:
    if uploaded_file.name.endswith(".csv"):
        return pd.read_csv(uploaded_file)
    elif uploaded_file.name.endswith(".xlsx"):
        return pd.read_excel(uploaded_file)
    else:
        raise ValueError("Unsupported file type")

def extract_timestamp(line):
    match = timestamp_pattern.search(line)
    if not match:
        return datetime.min
    clean = match.group().replace('[', '').replace(']', '')
    return datetime.fromisoformat(clean.split(' #')[0])

def group_logs_by_request_id(texts, request_ids):
    grouped = {req_id: [] for req_id in request_ids}

    for line in texts:
        if line.strip() == "":
            next 
        for req_id in request_ids:
            if req_id in line:
                grouped[req_id].append(line)

    for req_id, logs in grouped.items():
        grouped[req_id] = sorted(logs, key=extract_timestamp)
    return grouped

def build_grouped_log_text(grouped_logs):
    output_lines = []

    for req_id, lines in grouped_logs.items():
        if not lines:
            continue

        output_lines.append(f"\n===== REQUEST ID: {req_id} =====")
        output_lines.extend(lines)

    return "\n".join(output_lines)

def select_pattern():
    pattern_type = st.selectbox(
                "Pattern type",
                list(predefined_patterns.keys())
            )

    if pattern_type == "Custom Regex":
        pattern = st.text_input(
            "Enter custom regex",
            placeholder="e.g. request_id=([a-z0-9-]+)"
        )
    else:
        pattern = predefined_patterns[pattern_type]
        st.code(pattern, language="regex")
    return pattern

# Session state
if "request_ids" not in st.session_state:
    st.session_state.request_ids = []

# Tabs
tab1, tab2 = st.tabs(["📄 Request ID Extractor", "📜 Log Extractor"])

# TAB 1: Request ID Extractor
with tab1:
    st.subheader("Extract Request IDs from CSV / Excel")

    uploaded_file = st.file_uploader(
        "Upload CSV or Excel file",
        type= accepted_files
    )

    if uploaded_file:
        try:
            df = read_uploaded_file(uploaded_file)
            st.success(f"Loaded file with {len(df)} rows")

            column = st.selectbox("Select column to scan", df.columns)

            st.markdown("### Choose Request ID Pattern")

            pattern = select_pattern()

            if st.button("🔍 Extract Request IDs"):
                if not pattern:
                    st.error("Regex pattern cannot be empty")
                else:
                    texts = df[column].astype(str).tolist()
                    request_ids = extract_request_ids(texts, pattern)
                     
                    joined_request_ids = "|".join(request_ids)
                    st.session_state.request_ids = request_ids

                    st.success(f"Extracted {len(request_ids)} unique request IDs")

                    st.markdown("### Extracted IDs")
                    st.code(joined_request_ids, line_numbers=True, wrap_lines=True)

                    st.download_button(
                        "⬇️ Download request_ids.txt",
                        joined_request_ids,
                        file_name="request_ids.txt"
                    )

        except Exception as e:
            st.error(f"Failed to process file: {e}")

# TAB 2: Log Extractor
with tab2:
    st.subheader("Extract Complete Logs by Request ID")

    log_files = st.file_uploader(
        "Upload CSV/Excel files",
        type= accepted_files
    )

    if log_files:
        try:
            df = read_uploaded_file(log_files)
            if df is None:
                raise "Failed to process file"
            
            st.success(f"Loaded file with {len(df)} rows")

            st.markdown("### How do you want to get Request IDs?")

            mode = st.radio(
                "Request ID source",
                [
                    "Use request IDs from Tab 1",
                    "Enter request IDs manually",
                    "Extract request IDs using regex (from uploaded files)"
                ]
            )

            request_ids = []
            column = st.selectbox("Select column to scan", df.columns, key="log_column_select")
            texts = df[column].astype(str).tolist()
            if mode == "Use request IDs from Tab 1":
                request_ids = st.session_state.request_ids
                st.info(f"Using {len(request_ids)} request IDs from Tab 1")
            elif mode == "Enter request IDs manually":
                request_id_text = st.text_area(
                    "Paste request IDs (one per line)"
                )
                if request_id_text:
                    request_ids = [
                        line.strip()
                        for line in request_id_text.splitlines()
                        if line.strip()
                    ]
            elif mode == "Extract request IDs using regex (from uploaded files)":
                pattern = select_pattern()

                if pattern and df is not None:
                    request_ids = extract_request_ids(texts, pattern)
                    st.info(f"Extracted {len(request_ids)} request IDs using regex")
        except Exception as e:
            st.error(f"Errror: {e}")

        # FINAL ACTION
        if st.button("📎 Extract Complete Logs"):
            if not log_files:
                st.error("Please upload log files")
            elif not request_ids:
                st.error("No request IDs found")
            else:
                grouped_logs = group_logs_by_request_id(texts, request_ids)
                full_log_text = build_grouped_log_text(grouped_logs)

                st.success("Complete logs extracted")

                st.text_area(
                    "Complete Logs (grouped by request ID)",
                    full_log_text,
                    height=500
                )

                st.download_button(
                    label="⬇️ Download complete_logs.log",
                    data=full_log_text,
                    file_name="complete_logs.log",
                    mime="text/plain"
                )

# Footer
st.caption("Built with ❤️ for myself.")

