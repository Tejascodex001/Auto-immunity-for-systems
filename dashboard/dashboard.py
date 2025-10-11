import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="AIS | Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Cybersecurity Theme ---
st.markdown("""
<style>
    /* Import Modern Font */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap');
    
    /* Global Styling */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Fix content width and disable ALL animations */
    .main .block-container {
        max-width: 100%;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    
    /* Prevent ALL animations and transitions globally */
    *, *::before, *::after {
        animation: none !important;
        transition: none !important;
    }
    
    .main, .block-container, [data-testid="stVerticalBlock"], 
    [data-testid="stHorizontalBlock"], .element-container {
        animation: none !important;
        transition: none !important;
    }
    
    /* Main Title Styling */
    h1 {
        font-family: 'Orbitron', sans-serif !important;
        background: linear-gradient(90deg, #00d4ff 0%, #0099ff 50%, #00d4ff 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        font-weight: 700;
        text-shadow: 0 0 10px rgba(0, 212, 255, 0.3);
        letter-spacing: 2px;
    }
    
    /* Headings */
    h2, h3 {
        font-family: 'Orbitron', sans-serif !important;
        color: #00d4ff !important;
        font-weight: 600;
        letter-spacing: 1px;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1b2a 0%, #1b263b 100%);
        border-right: 2px solid #00d4ff;
        box-shadow: 5px 0 20px rgba(0, 212, 255, 0.3);
    }
    
    [data-testid="stSidebar"] h1, 
    [data-testid="stSidebar"] h2, 
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {
        color: #00d4ff !important;
        font-family: 'Orbitron', sans-serif;
    }
    
    /* Metric Cards */
    [data-testid="stMetricValue"] {
        font-family: 'Orbitron', sans-serif;
        font-size: 2.5rem !important;
        font-weight: 700;
    }
    
    [data-testid="stMetricLabel"] {
        font-family: 'Rajdhani', sans-serif;
        font-size: 1.1rem !important;
        color: #8892b0 !important;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    div[data-testid="stMetric"] {
        padding: 25px;
        border-radius: 15px;
        border: 2px solid;
    }
    
    div[data-testid="stMetric"]:hover {
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
    }
    
    /* Metric color variants */
    div[data-testid="column"]:nth-child(1) div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1e3a5f 0%, #2a4a7f 100%);
        border-color: #3b82f6;
    }
    div[data-testid="column"]:nth-child(1) [data-testid="stMetricValue"] {
        color: #60a5fa !important;
    }
    
    div[data-testid="column"]:nth-child(2) div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #5f1e1e 0%, #7f2a2a 100%);
        border-color: #ef4444;
    }
    div[data-testid="column"]:nth-child(2) [data-testid="stMetricValue"] {
        color: #f87171 !important;
    }
    
    div[data-testid="column"]:nth-child(3) div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #5f4a1e 0%, #7f632a 100%);
        border-color: #f59e0b;
    }
    div[data-testid="column"]:nth-child(3) [data-testid="stMetricValue"] {
        color: #fbbf24 !important;
    }
    
    div[data-testid="column"]:nth-child(4) div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1e5f4a 0%, #2a7f63 100%);
        border-color: #10b981;
    }
    div[data-testid="column"]:nth-child(4) [data-testid="stMetricValue"] {
        color: #34d399 !important;
    }
    
    /* Info/Success/Error Boxes */
    .stAlert {
        background: rgba(30, 42, 58, 0.9) !important;
        border: 1px solid #00d4ff !important;
        border-radius: 10px;
        color: #00d4ff !important;
        font-family: 'Rajdhani', sans-serif;
        font-weight: 500;
    }
    
    /* Dataframe Styling */
    [data-testid="stDataFrame"] {
        background: rgba(13, 27, 42, 0.8);
        border-radius: 15px;
        border: 1px solid #00d4ff40;
        box-shadow: 0 8px 32px rgba(0, 212, 255, 0.15);
        animation: none !important;
    }
    
    /* Column containers */
    [data-testid="column"] {
        animation: none !important;
        transition: none !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0066cc 0%, #00d4ff 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 30px;
        font-family: 'Orbitron', sans-serif;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    
    .stButton > button:hover {
        box-shadow: 0 6px 25px rgba(0, 212, 255, 0.5);
        background: linear-gradient(135deg, #00d4ff 0%, #0066cc 100%);
    }
    
    /* Radio Buttons */
    .stRadio > label {
        font-family: 'Rajdhani', sans-serif;
        color: #00d4ff !important;
        font-weight: 600;
    }
    
    /* Multiselect */
    .stMultiSelect > label {
        font-family: 'Rajdhani', sans-serif;
        color: #00d4ff !important;
        font-weight: 600;
    }
    
    /* File Uploader */
    [data-testid="stFileUploader"] {
        background: rgba(30, 42, 58, 0.6);
        border: 2px dashed #00d4ff;
        border-radius: 15px;
        padding: 20px;
    }
    
    [data-testid="stFileUploader"]:hover {
        border-color: #0099ff;
        background: rgba(30, 42, 58, 0.8);
        box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
    }
    
    /* Divider */
    hr {
        border-color: #00d4ff40 !important;
        margin: 2rem 0;
    }
    
    /* Custom Card Styling */
    .cyber-card {
        background: linear-gradient(135deg, rgba(30, 42, 58, 0.9) 0%, rgba(42, 63, 95, 0.9) 100%);
        padding: 25px;
        border-radius: 15px;
        border: 1px solid #00d4ff40;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.15);
        margin: 15px 0;
    }
    
    .cyber-card:hover {
        box-shadow: 0 8px 25px rgba(0, 212, 255, 0.25);
        border-color: #00d4ff;
    }
    
    /* Icons */
    .icon {
        font-size: 2rem;
        color: #00d4ff;
        filter: drop-shadow(0 0 10px #00d4ff);
    }
    
    /* Plotly Charts Dark Theme */
    .js-plotly-plot {
        background: transparent !important;
    }
    
    /* Subheader styling */
    .stSubheader {
        font-family: 'Orbitron', sans-serif;
        color: #00d4ff !important;
    }
    
    /* Text color */
    p, span, div {
        color: #8892b0;
    }
    
    /* Markdown */
    .stMarkdown {
        color: #8892b0;
    }
    
    /* Success message */
    .element-container:has(> .stSuccess) {
        animation: none !important;
    }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---
@st.cache_data(show_spinner="🔐 Decrypting and loading JSONL data...")
def load_jsonl_data(uploaded_file):
    if uploaded_file is None: return pd.DataFrame()
    records = [json.loads(line) for line in uploaded_file.getvalue().decode("utf-8").splitlines() if line]
    return pd.DataFrame(records) if records else pd.DataFrame()

@st.cache_data(show_spinner="🔐 Decrypting and loading CSV data...")
def load_csv_data(uploaded_file):
    if uploaded_file is None: return pd.DataFrame()
    df = pd.read_csv(uploaded_file)
    column_mapping = {
        'time': 'timestamp', 'ip': 'source_ip', 'attack_type': 'threat_type',
        'risk': 'risk_level', 'action': 'recommended_actions'
    }
    df = df.rename(columns=column_mapping)
    return df

@st.cache_data(show_spinner="🔐 Decrypting and loading JSON data...")
def load_json_data(uploaded_file):
    if uploaded_file is None: return pd.DataFrame()
    data = json.loads(uploaded_file.getvalue().decode("utf-8"))
    if isinstance(data, dict) and 'events' in data:
        return pd.DataFrame(data['events'])
    elif isinstance(data, list):
        return pd.DataFrame(data)
    return pd.DataFrame()

def standardize_dataframe(df):
    required_columns = {
        'timestamp': 'N/A', 'source_ip': 'Unknown', 'threat_type': 'Unknown',
        'risk_level': 'n/a', 'is_attack': False, 'confidence': 0.0,
        'summary': 'No summary provided.'
    }
    for col, default_val in required_columns.items():
        if col not in df.columns:
            df[col] = default_val
    
    df['risk_level'] = df['risk_level'].fillna('n/a').astype(str).str.lower()
    df['threat_type'] = df['threat_type'].fillna('Unknown').astype(str)
    df['source_ip'] = df['source_ip'].fillna('Unknown').astype(str)
    
    if df['is_attack'].dtype != bool:
        df['is_attack'] = df['is_attack'].apply(lambda x: True if str(x).lower() in ['yes', 'true'] else False)
        
    return df

# --- Main Dashboard ---
st.markdown("<h1>🛡️ AIS THREAT INTELLIGENCE PLATFORM</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #8892b0; font-size: 1.2rem; font-family: Rajdhani; margin-top: -20px;'>Real-time Security Event Analysis & Threat Detection System</p>", unsafe_allow_html=True)

# --- Sidebar ---
with st.sidebar:
    st.markdown("### 🎯 MISSION CONTROL")
    st.markdown("---")
    
    st.markdown("#### 📡 DATA INGESTION")
    file_format = st.radio(
        "Select Intelligence Format:",
        ["JSONL", "CSV", "JSON"],
        help="Choose the format of your threat intelligence data"
    )
    
    uploader_key = f"{file_format.lower()}_uploader"
    file_type = [file_format.lower()] if file_format != "JSONL" else ['jsonl']
    uploaded_file = st.file_uploader(
        f"📂 Upload {file_format} Data",
        type=file_type,
        key=uploader_key,
        help=f"Upload your {file_format} analysis file for processing"
    )

# --- Main Content ---
if uploaded_file is not None:
    # Load data
    if file_format == "JSONL": df = load_jsonl_data(uploaded_file)
    elif file_format == "CSV": df = load_csv_data(uploaded_file)
    else: df = load_json_data(uploaded_file)
    
    df = standardize_dataframe(df)

    if not df.empty:
        with st.sidebar:
            st.success(f"✅ **{len(df):,}** Events Loaded")
            st.markdown("---")
            
            st.markdown("#### 🔍 FILTER CONTROLS")
            
            attack_filter = st.radio(
                "Event Classification:",
                ["All Events", "🔴 Attacks Only", "🟢 Normal Only"],
                index=0,
                help="Filter events by attack classification"
            )
            
            if attack_filter == "🔴 Attacks Only": 
                df = df[df['is_attack'] == True]
            elif attack_filter == "🟢 Normal Only": 
                df = df[df['is_attack'] == False]
            
            risk_levels = sorted(df['risk_level'].unique())
            selected_risks = st.multiselect(
                '⚠️ Risk Level:',
                risk_levels,
                default=risk_levels,
                help="Filter by threat risk levels"
            )
            
            threat_types = sorted(df['threat_type'].unique())
            selected_threats = st.multiselect(
                '🎯 Threat Type:',
                threat_types,
                default=threat_types,
                help="Filter by threat classification"
            )
            
            filtered_df = df[df['risk_level'].isin(selected_risks) & df['threat_type'].isin(selected_threats)]

        # --- Metrics Section ---
        st.markdown("## 📊 THREAT LANDSCAPE OVERVIEW")
        
        total_events = len(filtered_df)
        attack_events = len(filtered_df[filtered_df['is_attack'] == True])
        high_risk_events = len(filtered_df[filtered_df['risk_level'].isin(['high', 'critical'])])
        attack_rate = (attack_events / total_events * 100) if total_events > 0 else 0
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "🔷 TOTAL EVENTS",
                f"{total_events:,}",
                help="Total number of security events detected"
            )
        
        with col2:
            st.metric(
                "🔴 ATTACKS DETECTED",
                f"{attack_events:,}",
                delta=f"{attack_rate:.1f}% of total",
                delta_color="inverse",
                help="Number of confirmed attack events"
            )
        
        with col3:
            st.metric(
                "⚠️ HIGH RISK EVENTS",
                f"{high_risk_events:,}",
                help="Critical and high severity threats"
            )
        
        with col4:
            unique_ips = filtered_df['source_ip'].nunique()
            st.metric(
                "🌐 UNIQUE SOURCES",
                f"{unique_ips:,}",
                help="Number of unique IP addresses"
            )
        
        st.markdown("---")

        # --- Visualizations ---
        st.markdown("## 📈 THREAT INTELLIGENCE ANALYTICS")
        
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🎯 Risk Level Distribution")
            risk_counts = filtered_df['risk_level'].value_counts()
            
            color_map = {
                'n/a': '#64748b',
                'low': '#22c55e',
                'medium': '#eab308',
                'high': '#f97316',
                'critical': '#ef4444'
            }
            colors = [color_map.get(risk, '#00d4ff') for risk in risk_counts.index]
            
            fig_risk = go.Figure(data=[
                go.Bar(
                    x=risk_counts.index,
                    y=risk_counts.values,
                    marker=dict(
                        color=colors,
                        line=dict(color='rgba(255,255,255,0.2)', width=1),
                        opacity=0.9
                    ),
                    hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>'
                )
            ])
            
            fig_risk.update_layout(
                plot_bgcolor='rgba(13, 27, 42, 0.6)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Rajdhani', color='#a0aec0', size=13),
                xaxis=dict(
                    title='Risk Level',
                    gridcolor='rgba(255, 255, 255, 0.05)',
                    showline=True,
                    linecolor='rgba(255, 255, 255, 0.1)',
                    title_font=dict(color='#00d4ff', size=14)
                ),
                yaxis=dict(
                    title='Event Count',
                    gridcolor='rgba(255, 255, 255, 0.05)',
                    showline=True,
                    linecolor='rgba(255, 255, 255, 0.1)',
                    title_font=dict(color='#00d4ff', size=14)
                ),
                hovermode='x',
                margin=dict(t=20, b=20, l=50, r=20)
            )
            
            st.plotly_chart(fig_risk, use_container_width=True, config={'displayModeBar': False})

        with col2:
            st.markdown("### 🎪 Top Threat Vectors")
            threat_counts = filtered_df['threat_type'].value_counts().nlargest(10)
            
            # Create gradient colors for threats
            threat_colors = ['#8b5cf6', '#a78bfa', '#c4b5fd', '#e879f9', '#f0abfc', 
                           '#fb923c', '#fdba74', '#fcd34d', '#fde047', '#bef264']
            
            fig_threat = go.Figure(data=[
                go.Bar(
                    y=threat_counts.index,
                    x=threat_counts.values,
                    orientation='h',
                    marker=dict(
                        color=threat_colors[:len(threat_counts)],
                        line=dict(color='rgba(255,255,255,0.2)', width=1),
                        opacity=0.9
                    ),
                    hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>'
                )
            ])
            
            fig_threat.update_layout(
                plot_bgcolor='rgba(13, 27, 42, 0.6)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Rajdhani', color='#a0aec0', size=13),
                xaxis=dict(
                    title='Event Count',
                    gridcolor='rgba(255, 255, 255, 0.05)',
                    showline=True,
                    linecolor='rgba(255, 255, 255, 0.1)',
                    title_font=dict(color='#00d4ff', size=14)
                ),
                yaxis=dict(
                    title='',
                    categoryorder='total ascending',
                    gridcolor='rgba(255, 255, 255, 0.05)',
                    showline=True,
                    linecolor='rgba(255, 255, 255, 0.1)'
                ),
                hovermode='y',
                margin=dict(t=20, b=20, l=180, r=20)
            )
            
            st.plotly_chart(fig_threat, use_container_width=True, config={'displayModeBar': False})

        # --- Attack Pie Chart ---
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🛡️ Attack vs Normal Traffic")
            attack_dist = filtered_df['is_attack'].value_counts()
            labels = ['Normal Traffic', 'Attacks'] if False in attack_dist.index else ['Attacks']
            values = [attack_dist.get(False, 0), attack_dist.get(True, 0)]
            
            fig_pie = go.Figure(data=[
                go.Pie(
                    labels=labels,
                    values=values,
                    marker=dict(
                        colors=['#22c55e', '#ef4444'],
                        line=dict(color='rgba(255,255,255,0.3)', width=2)
                    ),
                    hole=0.4,
                    textfont=dict(size=14, color='white', family='Rajdhani'),
                    hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
                )
            ])
            
            fig_pie.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Rajdhani', color='#a0aec0', size=13),
                showlegend=True,
                legend=dict(
                    font=dict(color='#a0aec0'),
                    bgcolor='rgba(13, 27, 42, 0.6)'
                ),
                margin=dict(t=20, b=20)
            )
            
            st.plotly_chart(fig_pie, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            st.markdown("### 🌐 Top Source IPs")
            ip_counts = filtered_df[filtered_df['is_attack'] == True]['source_ip'].value_counts().nlargest(8)
            
            if not ip_counts.empty:
                # Create gradient from red to orange
                ip_colors = ['#dc2626', '#ea580c', '#f97316', '#fb923c', 
                           '#fdba74', '#fcd34d', '#fde047', '#facc15']
                
                fig_ip = go.Figure(data=[
                    go.Bar(
                        x=ip_counts.values,
                        y=ip_counts.index,
                        orientation='h',
                        marker=dict(
                            color=ip_colors[:len(ip_counts)],
                            line=dict(color='rgba(255,255,255,0.2)', width=1),
                            opacity=0.9
                        ),
                        hovertemplate='<b>%{y}</b><br>Attacks: %{x}<extra></extra>'
                    )
                ])
                
                fig_ip.update_layout(
                    plot_bgcolor='rgba(13, 27, 42, 0.6)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(family='Rajdhani', color='#a0aec0', size=13),
                    xaxis=dict(
                        title='Attack Count',
                        gridcolor='rgba(255, 255, 255, 0.05)',
                        showline=True,
                        linecolor='rgba(255, 255, 255, 0.1)',
                        title_font=dict(color='#00d4ff', size=14)
                    ),
                    yaxis=dict(
                        title='',
                        categoryorder='total ascending',
                        gridcolor='rgba(255, 255, 255, 0.05)',
                        title_font=dict(color='#00d4ff', size=14)
                    ),
                    margin=dict(t=20, b=20, l=150, r=20)
                )
                
                st.plotly_chart(fig_ip, use_container_width=True, config={'displayModeBar': False})
            else:
                st.info("No attack source IPs to display")

        st.markdown("---")

        # --- Detailed Event Log ---
        st.markdown("## 📋 SECURITY EVENT INTELLIGENCE LOG")
        
        display_df = filtered_df[['timestamp', 'threat_type', 'risk_level', 'source_ip', 'summary']].copy()
        
        # Style the dataframe
        def highlight_risk(row):
            if row['risk_level'] == 'critical':
                return ['background-color: rgba(220, 53, 69, 0.3)'] * len(row)
            elif row['risk_level'] == 'high':
                return ['background-color: rgba(253, 126, 20, 0.3)'] * len(row)
            elif row['risk_level'] == 'medium':
                return ['background-color: rgba(255, 193, 7, 0.2)'] * len(row)
            else:
                return [''] * len(row)
        
        st.dataframe(
            display_df.style.apply(highlight_risk, axis=1),
            use_container_width=True,
            height=400
        )
        
        st.info(f"📊 Displaying **{len(filtered_df):,}** of **{len(df):,}** total events | Filters: {attack_filter}")
        
    else:
        st.error("⚠️ **DATA PARSING ERROR** - The uploaded file is empty or malformed. Please verify file integrity.")
else:
    # Welcome Screen
    st.markdown("""
    <div style='text-align: center; padding: 50px;'>
        <h2 style='color: #00d4ff; font-family: Orbitron;'>🔐 SYSTEM READY</h2>
        <p style='font-size: 1.2rem; color: #8892b0; font-family: Rajdhani;'>
            Awaiting threat intelligence data upload...
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class='cyber-card'>
            <h3 style='color: #00d4ff;'>📡 JSONL Format</h3>
            <p>Raw, detailed pipeline output from AIS threat detection system.</p>
            <p><strong>File:</strong> analysis_results.jsonl</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='cyber-card'>
            <h3 style='color: #00d4ff;'>📊 CSV Format</h3>
            <p>Structured summary reports with aggregated threat metrics.</p>
            <p><strong>File:</strong> summary_*.csv</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class='cyber-card'>
            <h3 style='color: #00d4ff;'>📄 JSON Format</h3>
            <p>Hierarchical threat intelligence data with nested event structures.</p>
            <p><strong>File:</strong> summary_*.json</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<p style='text-align: center; color: #8892b0; margin-top: 40px; font-family: Rajdhani;'>⬅️ Use the sidebar to upload your threat intelligence data and begin analysis</p>", unsafe_allow_html=True)