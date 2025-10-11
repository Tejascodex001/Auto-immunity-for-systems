import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="RAG Security Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Helper Functions to Load Data ---
@st.cache_data
def load_jsonl_data(uploaded_file):
    """Loads analysis data from a .jsonl file."""
    if uploaded_file is None:
        return pd.DataFrame()
    
    records = []
    file_content = uploaded_file.getvalue().decode("utf-8").splitlines()
    for line in file_content:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    
    if not records:
        return pd.DataFrame()
        
    df = pd.DataFrame(records)
    
    # Standardize column names
    if 'risk_level' in df.columns:
        df['risk_level'] = df['risk_level'].str.lower()
    if 'threat_type' in df.columns:
        df['threat_type'] = df['threat_type'].fillna('Unknown')
    if 'source_ip' in df.columns:
        df['source_ip'] = df['source_ip'].fillna('Unknown')
    
    # Add is_attack column if not present
    if 'is_attack' not in df.columns:
        df['is_attack'] = False
    
    return df

@st.cache_data
def load_csv_data(uploaded_file):
    """Loads analysis data from a .csv file."""
    if uploaded_file is None:
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(uploaded_file)
        
        # Standardize column names for CSV
        # Map common CSV column names to standard format
        column_mapping = {
            'time': 'timestamp',
            'ip': 'source_ip',
            'attack_type': 'threat_type',
            'risk': 'risk_level',
            'action': 'recommended_actions'
        }
        
        df = df.rename(columns=column_mapping)
        
        # Standardize values
        if 'risk_level' in df.columns:
            df['risk_level'] = df['risk_level'].str.lower()
        if 'threat_type' in df.columns:
            df['threat_type'] = df['threat_type'].fillna('Unknown')
        if 'source_ip' in df.columns:
            df['source_ip'] = df['source_ip'].fillna('Unknown')
        
        # Handle is_attack column
        if 'is_attack' in df.columns:
            # Convert string Yes/No to boolean
            df['is_attack'] = df['is_attack'].map({'Yes': True, 'No': False})
        else:
            # Infer from threat_type
            df['is_attack'] = df.get('threat_type', 'Normal') != 'Normal'
        
        return df
    except Exception as e:
        st.error(f"Error loading CSV: {e}")
        return pd.DataFrame()

@st.cache_data
def load_json_data(uploaded_file):
    """Loads analysis data from a .json file."""
    if uploaded_file is None:
        return pd.DataFrame()
    
    try:
        file_content = uploaded_file.getvalue().decode("utf-8")
        data = json.loads(file_content)
        
        # Handle different JSON structures
        if isinstance(data, dict) and 'events' in data:
            df = pd.DataFrame(data['events'])
        elif isinstance(data, list):
            df = pd.DataFrame(data)
        else:
            return pd.DataFrame()
        
        # Standardize values
        if 'risk_level' in df.columns:
            df['risk_level'] = df['risk_level'].str.lower()
        if 'threat_type' in df.columns:
            df['threat_type'] = df['threat_type'].fillna('Unknown')
        if 'source_ip' in df.columns:
            df['source_ip'] = df['source_ip'].fillna('Unknown')
        
        # Handle is_attack column
        if 'is_attack' in df.columns:
            if df['is_attack'].dtype == 'object':
                df['is_attack'] = df['is_attack'].map({'Yes': True, 'No': False})
        else:
            df['is_attack'] = df.get('threat_type', 'Normal') != 'Normal'
        
        return df
    except Exception as e:
        st.error(f"Error loading JSON: {e}")
        return pd.DataFrame()

def standardize_dataframe(df):
    """Ensure all required columns exist with defaults."""
    required_columns = {
        'timestamp': 'N/A',
        'source_ip': 'Unknown',
        'threat_type': 'Unknown',
        'risk_level': 'n/a',
        'is_attack': False,
        'confidence': 0.0
    }
    
    for col, default_val in required_columns.items():
        if col not in df.columns:
            df[col] = default_val
    
    return df

# --- Main Dashboard UI ---

st.title("🛡️ RAG Security Log Analysis Dashboard")
st.markdown("Visualize security events analyzed by the RAG-based LLM system.")

# --- Sidebar for File Upload and Filters ---
st.sidebar.header("📁 Data Upload")

# File format selection
file_format = st.sidebar.radio(
    "Select file format to upload:",
    options=["JSONL", "CSV", "JSON"],
    help="Choose the format of your analysis results file"
)

# File uploader based on selected format
if file_format == "JSONL":
    uploaded_file = st.sidebar.file_uploader(
        "Upload your `analysis_results.jsonl` file",
        type=['jsonl'],
        key="jsonl_uploader"
    )
elif file_format == "CSV":
    uploaded_file = st.sidebar.file_uploader(
        "Upload your summary CSV file",
        type=['csv'],
        key="csv_uploader"
    )
else:  # JSON
    uploaded_file = st.sidebar.file_uploader(
        "Upload your summary JSON file",
        type=['json'],
        key="json_uploader"
    )

# --- Dashboard Logic ---
if uploaded_file is not None:
    # Load data based on format
    if file_format == "JSONL":
        df = load_jsonl_data(uploaded_file)
    elif file_format == "CSV":
        df = load_csv_data(uploaded_file)
    else:  # JSON
        df = load_json_data(uploaded_file)
    
    # Standardize dataframe
    df = standardize_dataframe(df)

    if not df.empty:
        st.sidebar.success(f"✓ Loaded {len(df)} events from {file_format} file")
        
        # --- Sidebar Filters ---
        st.sidebar.markdown("---")
        st.sidebar.subheader("🔍 Filter Events")
        
        # Filter by Attack Status
        attack_filter = st.sidebar.radio(
            "Show:",
            options=["All Events", "Attacks Only", "Normal Events"],
            index=0
        )
        
        if attack_filter == "Attacks Only":
            df = df[df['is_attack'] == True]
        elif attack_filter == "Normal Events":
            df = df[df['is_attack'] == False]
        
        # Filter by Risk Level
        risk_levels = sorted(df['risk_level'].unique())
        selected_risks = st.sidebar.multiselect(
            'Risk Level:',
            options=risk_levels,
            default=risk_levels
        )
        
        # Filter by Threat Type
        threat_types = sorted(df['threat_type'].unique())
        selected_threats = st.sidebar.multiselect(
            'Threat Type:',
            options=threat_types,
            default=threat_types
        )
        
        # Filter by Source IP (optional)
        if st.sidebar.checkbox("Filter by Source IP"):
            unique_ips = sorted(df['source_ip'].unique())
            selected_ips = st.sidebar.multiselect(
                'Source IP:',
                options=unique_ips
            )
            if selected_ips:
                df = df[df['source_ip'].isin(selected_ips)]
        
        # Apply filters
        filtered_df = df[
            df['risk_level'].isin(selected_risks) &
            df['threat_type'].isin(selected_threats)
        ]

        # --- Main Page Content ---
        
        # 1. Key Performance Indicators (KPIs)
        st.header("📊 High-Level Overview")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        total_events = len(filtered_df)
        attack_events = len(filtered_df[filtered_df['is_attack'] == True])
        high_risk_events = len(filtered_df[filtered_df['risk_level'].isin(['high', 'critical'])])
        unique_threats = filtered_df['threat_type'].nunique()
        unique_ips = filtered_df['source_ip'].nunique()
        
        col1.metric("Total Events", f"{total_events}")
        col2.metric("Attacks Detected", f"{attack_events}", 
                   delta=f"{100*attack_events/total_events:.1f}%" if total_events > 0 else "0%")
        col3.metric("High/Critical Risk", f"{high_risk_events}")
        col4.metric("Unique Threats", f"{unique_threats}")
        col5.metric("Unique IPs", f"{unique_ips}")
        
        st.markdown("---")

        # 2. Visualizations
        st.header("📈 Event Distribution")
        
        viz_row1_col1, viz_row1_col2 = st.columns(2)

        with viz_row1_col1:
            st.subheader("Events by Risk Level")
            risk_counts = filtered_df['risk_level'].value_counts()
            
            # Define color mapping
            color_map = {
                'n/a': '#B0B0B0',
                'low': '#28a745',
                'medium': '#ffc107',
                'high': '#fd7e14',
                'critical': '#dc3545'
            }
            
            colors = [color_map.get(risk, '#6c757d') for risk in risk_counts.index]
            
            fig_risk = go.Figure(data=[
                go.Bar(
                    x=risk_counts.index,
                    y=risk_counts.values,
                    marker_color=colors,
                    text=risk_counts.values,
                    textposition='auto'
                )
            ])
            fig_risk.update_layout(
                xaxis_title="Risk Level",
                yaxis_title="Number of Events",
                showlegend=False
            )
            st.plotly_chart(fig_risk, use_container_width=True)

        with viz_row1_col2:
            st.subheader("Attack vs Normal Events")
            attack_counts = filtered_df['is_attack'].value_counts()
            
            fig_attack = px.pie(
                values=attack_counts.values,
                names=['Attack' if x else 'Normal' for x in attack_counts.index],
                hole=0.4,
                color_discrete_sequence=['#dc3545', '#28a745']
            )
            st.plotly_chart(fig_attack, use_container_width=True)
        
        viz_row2_col1, viz_row2_col2 = st.columns(2)
        
        with viz_row2_col1:
            st.subheader("Top 10 Threat Types")
            threat_counts = filtered_df['threat_type'].value_counts().head(10)
            fig_threat = px.bar(
                x=threat_counts.values,
                y=threat_counts.index,
                orientation='h',
                labels={'x': 'Count', 'y': 'Threat Type'}
            )
            fig_threat.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_threat, use_container_width=True)

        with viz_row2_col2:
            st.subheader("Top 10 Source IPs (Attacks)")
            attack_df = filtered_df[filtered_df['is_attack'] == True]
            if not attack_df.empty:
                ip_counts = attack_df['source_ip'].value_counts().head(10)
                fig_ip = px.bar(
                    x=ip_counts.values,
                    y=ip_counts.index,
                    orientation='h',
                    labels={'x': 'Attack Count', 'y': 'Source IP'},
                    color=ip_counts.values,
                    color_continuous_scale='Reds'
                )
                fig_ip.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig_ip, use_container_width=True)
            else:
                st.info("No attack events in filtered data")
        
        st.markdown("---")

        # 3. Time Series (if timestamp available)
        if 'timestamp' in filtered_df.columns and filtered_df['timestamp'].iloc[0] != 'N/A':
            st.header("📅 Timeline Analysis")
            try:
                # Try to parse timestamps
                filtered_df['parsed_time'] = pd.to_datetime(filtered_df['timestamp'], errors='coerce')
                
                if filtered_df['parsed_time'].notna().any():
                    timeline_df = filtered_df.dropna(subset=['parsed_time'])
                    timeline_df = timeline_df.set_index('parsed_time')
                    
                    # Events over time
                    events_over_time = timeline_df.resample('H').size()
                    
                    fig_timeline = px.line(
                        x=events_over_time.index,
                        y=events_over_time.values,
                        labels={'x': 'Time', 'y': 'Number of Events'},
                        title='Events Over Time (Hourly)'
                    )
                    st.plotly_chart(fig_timeline, use_container_width=True)
            except Exception as e:
                st.info("Timeline analysis not available for this data")
        
        st.markdown("---")

        # 4. Detailed Data View
        st.header("📋 Detailed Event Log")
        st.markdown("Browse, search, and sort all analyzed events.")
        
        # Display options
        col1, col2, col3 = st.columns(3)
        with col1:
            show_all_columns = st.checkbox("Show all columns", value=False)
        with col2:
            rows_to_show = st.selectbox("Rows per page:", [10, 25, 50, 100], index=1)
        with col3:
            export_format = st.selectbox("Export as:", ["None", "CSV", "JSON"])
        
        # Select columns to display
        if show_all_columns:
            display_df = filtered_df
        else:
            # Show key columns only
            key_columns = ['timestamp', 'source_ip', 'threat_type', 'risk_level', 'is_attack']
            if 'confidence' in filtered_df.columns:
                key_columns.append('confidence')
            available_cols = [col for col in key_columns if col in filtered_df.columns]
            display_df = filtered_df[available_cols]
        
        # Display the filtered dataframe
        st.dataframe(
            display_df,
            use_container_width=True,
            height=min(400, (rows_to_show + 1) * 35)
        )
        
        # Export functionality
        if export_format == "CSV":
            csv = display_df.to_csv(index=False)
            st.download_button(
                label="📥 Download CSV",
                data=csv,
                file_name=f"filtered_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        elif export_format == "JSON":
            json_str = display_df.to_json(orient='records', indent=2)
            st.download_button(
                label="📥 Download JSON",
                data=json_str,
                file_name=f"filtered_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        # Statistics summary
        with st.expander("📊 View Statistics Summary"):
            stat_col1, stat_col2 = st.columns(2)
            
            with stat_col1:
                st.markdown("**Risk Distribution:**")
                for risk, count in filtered_df['risk_level'].value_counts().items():
                    pct = 100 * count / len(filtered_df)
                    st.write(f"- {risk.upper()}: {count} ({pct:.1f}%)")
            
            with stat_col2:
                st.markdown("**Attack Status:**")
                for status, count in filtered_df['is_attack'].value_counts().items():
                    pct = 100 * count / len(filtered_df)
                    label = "Attacks" if status else "Normal"
                    st.write(f"- {label}: {count} ({pct:.1f}%)")

    else:
        st.warning("The uploaded file is empty or could not be parsed. Please check the file content.")

else:
    st.info("👋 Welcome! Please upload your analysis results file using the sidebar to get started.")
    
    st.markdown("---")
    st.subheader("📌 Supported File Formats:")
    st.markdown("""
    - **JSONL**: Full detailed analysis results (`analysis_results.jsonl`)
    - **CSV**: Clean summary files (`summary_*.csv`, `attacks_*.csv`)
    - **JSON**: Structured summary files (`summary_*.json`)
    
    Choose your preferred format in the sidebar and upload the corresponding file.
    """)
    
    # Show example data structure
    with st.expander("💡 Expected Data Structure"):
        st.markdown("**For CSV files:**")
        st.code("""
timestamp,source_ip,threat_type,risk_level,is_attack,confidence
2025-10-10 18:01:27,192.168.1.100,Normal,N/A,No,0.95
2025-10-10 18:02:38,103.207.39.21,Exploit,Critical,Yes,0.98
        """)
        
        st.markdown("**For JSONL files:**")
        st.code("""
{"timestamp": "2025-10-11T16:28:46", "source_ip": "192.168.1.100", "threat_type": "Normal", "risk_level": "N/A", "is_attack": false}
        """)