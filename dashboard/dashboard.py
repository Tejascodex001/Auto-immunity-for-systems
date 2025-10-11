import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# --- Page Configuration (must be the first Streamlit command) ---
st.set_page_config(
    page_title="AIS | Security Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Helper Functions to Load and Standardize Data ---
@st.cache_data(show_spinner="Loading JSONL data...")
def load_jsonl_data(uploaded_file):
    """Loads and preprocesses data from a .jsonl file."""
    if uploaded_file is None: return pd.DataFrame()
    records = [json.loads(line) for line in uploaded_file.getvalue().decode("utf-8").splitlines() if line]
    return pd.DataFrame(records) if records else pd.DataFrame()

@st.cache_data(show_spinner="Loading CSV data...")
def load_csv_data(uploaded_file):
    """Loads and preprocesses data from a .csv file."""
    if uploaded_file is None: return pd.DataFrame()
    df = pd.read_csv(uploaded_file)
    column_mapping = {
        'time': 'timestamp', 'ip': 'source_ip', 'attack_type': 'threat_type',
        'risk': 'risk_level', 'action': 'recommended_actions'
    }
    df = df.rename(columns=column_mapping)
    return df

@st.cache_data(show_spinner="Loading JSON data...")
def load_json_data(uploaded_file):
    """Loads and preprocesses data from a .json file."""
    if uploaded_file is None: return pd.DataFrame()
    data = json.loads(uploaded_file.getvalue().decode("utf-8"))
    if isinstance(data, dict) and 'events' in data:
        return pd.DataFrame(data['events'])
    elif isinstance(data, list):
        return pd.DataFrame(data)
    return pd.DataFrame()

def standardize_dataframe(df):
    """Ensures all required columns exist and have consistent data types."""
    required_columns = {
        'timestamp': 'N/A', 'source_ip': 'Unknown', 'threat_type': 'Unknown',
        'risk_level': 'n/a', 'is_attack': False, 'confidence': 0.0,
        'summary': 'No summary provided.'
    }
    for col, default_val in required_columns.items():
        if col not in df.columns:
            df[col] = default_val
    
    # Clean and standardize data types
    df['risk_level'] = df['risk_level'].fillna('n/a').astype(str).str.lower()
    df['threat_type'] = df['threat_type'].fillna('Unknown').astype(str)
    df['source_ip'] = df['source_ip'].fillna('Unknown').astype(str)
    
    if df['is_attack'].dtype != bool:
        df['is_attack'] = df['is_attack'].apply(lambda x: True if str(x).lower() in ['yes', 'true'] else False)
        
    return df

# --- Main Dashboard UI ---

st.title("🛡️ AIS - Security Log Analysis Dashboard")
st.markdown("Upload and visualize security events analyzed by the AI Security system.")

# --- Sidebar for File Upload ---
st.sidebar.header("📁 Data Upload")
file_format = st.sidebar.radio("Select file format:", ["JSONL", "CSV", "JSON"])

uploader_key = f"{file_format.lower()}_uploader"
file_type = [file_format.lower()] if file_format != "JSONL" else ['jsonl']
uploaded_file = st.sidebar.file_uploader(f"Upload your {file_format} analysis file", type=file_type, key=uploader_key)


# --- Main Logic: Process file and render dashboard ---
if uploaded_file is not None:
    # Load data based on selected format
    if file_format == "JSONL": df = load_jsonl_data(uploaded_file)
    elif file_format == "CSV": df = load_csv_data(uploaded_file)
    else: df = load_json_data(uploaded_file)
    
    df = standardize_dataframe(df)

    if not df.empty:
        st.sidebar.success(f"✓ Loaded {len(df):,} events.")
        
        # --- Sidebar Filters ---
        st.sidebar.markdown("---")
        st.sidebar.header("🔍 Filter Events")
        
        attack_filter = st.sidebar.radio("Show Events:", ["All", "Attacks Only", "Normal Only"], index=0)
        if attack_filter == "Attacks Only": df = df[df['is_attack'] == True]
        elif attack_filter == "Normal Only": df = df[df['is_attack'] == False]
        
        risk_levels = sorted(df['risk_level'].unique())
        selected_risks = st.sidebar.multiselect('Filter by Risk Level:', risk_levels, default=risk_levels)
        
        threat_types = sorted(df['threat_type'].unique())
        selected_threats = st.sidebar.multiselect('Filter by Threat Type:', threat_types, default=threat_types)
        
        filtered_df = df[df['risk_level'].isin(selected_risks) & df['threat_type'].isin(selected_threats)]

        # --- Main Page Content ---
        st.header("📊 High-Level Overview")
        total_events = len(filtered_df)
        attack_events = len(filtered_df[filtered_df['is_attack'] == True])
        high_risk_events = len(filtered_df[filtered_df['risk_level'].isin(['high', 'critical'])])
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Displayed Events", f"{total_events:,}")
        col2.metric("Attacks Detected", f"{attack_events:,}")
        col3.metric("High/Critical Risk Events", f"{high_risk_events:,}")
        
        st.markdown("---")

        # --- Visualizations ---
        st.header("📈 Visual Analytics")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Events by Risk Level")
            risk_counts = filtered_df['risk_level'].value_counts()
            color_map = {'n/a': '#B0B0B0', 'low': '#28a745', 'medium': '#ffc107', 'high': '#fd7e14', 'critical': '#dc3545'}
            colors = [color_map.get(risk, '#6c757d') for risk in risk_counts.index]
            fig_risk = go.Figure(data=[go.Bar(x=risk_counts.index, y=risk_counts.values, marker_color=colors)])
            st.plotly_chart(fig_risk, use_container_width=True, config={'displayModeBar': False})

        with col2:
            st.subheader("Top 10 Threat Types")
            threat_counts = filtered_df['threat_type'].value_counts().nlargest(10)
            fig_threat = px.bar(threat_counts, y=threat_counts.index, x=threat_counts.values, orientation='h', labels={'y': 'Threat Type', 'x': 'Count'})
            fig_threat.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_threat, use_container_width=True, config={'displayModeBar': False})

        # --- Detailed Data View ---
        st.header("📋 Detailed Event Log")
        st.dataframe(filtered_df[['timestamp', 'threat_type', 'risk_level', 'source_ip', 'summary']], use_container_width=True)
        st.info(f"Displaying {len(filtered_df)} of the originally loaded {len(df) if 'df' in locals() else 0} events.")
    else:
        st.error("The uploaded file is empty or could not be parsed. Please check the file content and format.")
else:
    st.info("👋 Welcome! Please upload your analysis results file using the sidebar to get started.")
    st.markdown("---")
    st.subheader("Supported File Formats:")
    st.markdown("- **JSONL**: The raw, detailed output from the AIS pipeline (`analysis_results.jsonl`).")
    st.markdown("- **CSV**: A summary file generated by the pipeline (`summary_*.csv`).")
    st.markdown("- **JSON**: A structured summary report from the pipeline (`summary_*.json`).")