import streamlit as st
import pandas as pd
import json
import plotly.express as px

# --- Page Configuration ---
# Use st.set_page_config() as the first Streamlit command.
st.set_page_config(
    page_title="RAG Security Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Helper Function to Load Data ---
@st.cache_data
def load_data(uploaded_file):
    """Loads analysis data from a .jsonl file."""
    if uploaded_file is None:
        return pd.DataFrame()
    
    records = []
    # To read the file content, we use getvalue() which returns bytes
    # and decode it to a string.
    file_content = uploaded_file.getvalue().decode("utf-8").splitlines()
    for line in file_content:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip malformed lines
            continue
    
    if not records:
        return pd.DataFrame()
        
    df = pd.DataFrame(records)
    # Ensure key columns exist to prevent errors
    for col in ['risk_level', 'threat_type', 'source_ip', 'summary']:
        if col not in df.columns:
            df[col] = 'N/A' # Add a default value if missing
            
    return df

# --- Main Dashboard UI ---

st.title("🛡️ RAG Security Log Analysis Dashboard")
st.markdown("Visualize security events analyzed by the RAG-based LLM system.")

# --- Sidebar for File Upload and Filters ---
st.sidebar.header("Controls")
uploaded_file = st.sidebar.file_uploader(
    "Upload your `analysis_results.jsonl` file",
    type=['jsonl']
)

# --- Dashboard Logic ---
if uploaded_file is not None:
    df = load_data(uploaded_file)

    if not df.empty:
        st.sidebar.success(f"Successfully loaded {len(df)} events.")
        
        # --- Sidebar Filters ---
        st.sidebar.subheader("Filter Events")
        
        # Filter by Risk Level
        risk_levels = df['risk_level'].unique()
        selected_risks = st.sidebar.multiselect(
            'Filter by Risk Level:',
            options=risk_levels,
            default=risk_levels
        )
        
        # Filter by Threat Type
        threat_types = df['threat_type'].unique()
        selected_threats = st.sidebar.multiselect(
            'Filter by Threat Type:',
            options=threat_types,
            default=threat_types
        )
        
        # Apply filters
        filtered_df = df[
            df['risk_level'].isin(selected_risks) &
            df['threat_type'].isin(selected_threats)
        ]

        # --- Main Page Content ---
        
        # 1. Key Performance Indicators (KPIs)
        st.header("High-Level Overview")
        col1, col2, col3, col4 = st.columns(4)
        
        total_events = len(filtered_df)
        high_risk_events = len(filtered_df[filtered_df['risk_level'].isin(['high', 'critical'])])
        unique_threats = filtered_df['threat_type'].nunique()
        unique_ips = filtered_df['source_ip'].nunique()
        
        col1.metric("Total Events Analyzed", f"{total_events}")
        col2.metric("High/Critical Risk Events", f"{high_risk_events}")
        col3.metric("Unique Threat Types", f"{unique_threats}")
        col4.metric("Unique Source IPs", f"{unique_ips}")
        
        st.markdown("---")

        # 2. Visualizations
        st.header("Event Distribution")
        viz_col1, viz_col2 = st.columns(2)

        with viz_col1:
            st.subheader("Events by Risk Level")
            risk_counts = filtered_df['risk_level'].value_counts()
            fig_risk = px.bar(
                risk_counts,
                x=risk_counts.index,
                y=risk_counts.values,
                labels={'x': 'Risk Level', 'y': 'Number of Events'},
                color=risk_counts.index,
                color_discrete_map={
                    'low': 'green',
                    'medium': 'orange',
                    'high': 'red',
                    'critical': 'darkred'
                }
            )
            st.plotly_chart(fig_risk, use_container_width=True)

        with viz_col2:
            st.subheader("Events by Threat Type")
            threat_counts = filtered_df['threat_type'].value_counts()
            fig_threat = px.pie(
                threat_counts,
                names=threat_counts.index,
                values=threat_counts.values,
                hole=0.3
            )
            st.plotly_chart(fig_threat, use_container_width=True)
            
        st.markdown("---")

        # 3. Detailed Data View
        st.header("Detailed Event Log")
        st.markdown("Browse, search, and sort all analyzed events.")
        
        # Display the filtered dataframe
        st.dataframe(filtered_df)

    else:
        st.warning("The uploaded file is empty or could not be parsed. Please check the file content.")

else:
    st.info("👋 Welcome! Please upload your `analysis_results.jsonl` file using the sidebar to get started.")