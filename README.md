cat > README.md << 'EOF'
# AIS: Auto Immunity for Systems

**AIS** is a self-learning security system that uses a hybrid AI approach to detect, analyze, and respond to cyber threats in real-time. It combines a Retrieval-Augmented Generation (RAG) pipeline using Large Language Models (LLMs) with a Reinforcement Learning (RL) agent to create a dynamic and intelligent defense mechanism.

---

## Project Architecture

The project is built on a modular, three-part architecture that simulates a complete cyber battleground:

1.  **Victim (`/test_web`):** A Dockerized Node.js web application with intentional vulnerabilities (SQL Injection, weak rate limiting). It generates detailed logs of all incoming traffic and events.

2.  **Attacker (`/attack_orchestrator`):** A Dockerized FastAPI application that acts as an "Attack Orchestrator." It exposes an API that can be used to launch controlled attacks (e.g., `curl`, `nmap`) against the Victim.

3.  **Defender (`/src` & `main_defender.py`):** The core AIS application. This is a persistent Python service running on the host machine that:
    *   **Parses** the Victim's logs in real-time.
    *   **Analyzes** threats using an LLM-based RAG system.
    *   **Decides** on the best action using a pre-trained Reinforcement Learning agent.
    *   **Executes** defensive actions (e.g., blocking IPs) via the Executor module.
 <!-- Optional: Add a link to an architecture diagram -->

---

## Getting Started

### Prerequisites

*   **Docker & Docker Compose:** Required to run the Victim and Attacker containers.
*   **Conda / Miniconda:** For managing the Python environments.
*   **Ollama:** For running the local LLM (`phi3:mini`). Make sure the model is pulled: `ollama pull phi3:mini`.
*   **An NVIDIA GPU** is highly recommended for the Defender's LLM component.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd AIS
    ```

2.  **Create the Conda Environment:**
    ```bash
    conda create -n ais python=3.11
    conda activate ais
    pip install -r requirements.txt
    ```

3.  **Train the RL Agent (One-time setup):**
    The RL agent must be trained on a historical dataset before the main system can run.
    ```bash
    # Make sure your training data (e.g., UNSW_finetuning.jsonl) is in the /data folder
    cd src/agents
    python train_agent.py
    # This will create the 'ais_rl_agent_ppo.zip' file.
    # Move the generated .zip file to the project's root directory.
    mv ais_rl_agent_ppo.zip ../../
    cd ../..
    ```

---

## Running the Full Demo

The demo requires three separate terminals running from the **root of the `AIS` project**.

**Terminal 1: Start the Environment (Victim & Attacker)**
```bash
docker-compose up --build -d
```
This will build and start the **victim-website** and **attacker-api containers**.

**Terminal 2: Start the Defender (AIS)**

```bash
conda activate ais
python main_defender.py
```
The AIS is now live and monitoring the victim's log file.

**Terminal 3: Launch the Attacks**

```bash
conda activate ais
python scripts/run_live_demo.py
```
Press Enter when prompted to begin the attack sequence. Observe the real-time analysis and decisions in the Defender's terminal.

---

## Viewing the Dashboard

The project includes a Streamlit dashboard to visualize the analysis results.

1.  Ensure the Defender has run and generated an analysis_results.jsonl file.

2.  Run the dashboard:
```bash
# From the project root directory
streamlit run dashboard/app.py
```

Upload the analysis_results.jsonl file in the web interface to see the visualizations

### What to Do After Running the Commands

1.  **Review the Files:** Open `requirements.txt` and `README.md` in your code editor to make sure they look correct.
2.  **Add Architecture Diagram (Optional but Recommended):** Create a simple diagram (using a tool like diagrams.net, Excalidraw, or even PowerPoint) that shows the three components (Victim, Attacker, Defender) and the flow of information between them. Upload this image to a service (like an anonymous image host or a GitHub issue) and paste the link into the `README.md`.
3.  **Commit to Git:** These are essential project files. Add them to your version control.
    ```bash
    git add requirements.txt README.md
    git commit -m "docs: Add initial README and project requirements"
    ```

You now have a well-documented and easily reproducible project.
