# Dockerfile

# Use a slim Python base image (which is a Debian Linux distribution)
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Install essential attack tools using the Linux package manager (apt-get)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    gobuster \
    curl \
    && rm -rf /var/lib/apt/lists/*

# --- NEW SECTION: Manually install the wordlist ---
# 1. Create the directory that will hold our wordlists
RUN mkdir -p /usr/share/wordlists

# 2. Download the common.txt wordlist from the trusted SecLists repository into our new directory
RUN curl -o /usr/share/wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
# --- END NEW SECTION ---

# Copy your application files from your Windows PC into the container
COPY ./requirements.txt /app/requirements.txt
COPY ./main.py /app/main.py

# Install Python dependencies inside the container
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

# Expose port 8000 so we can access the API from our Windows machine
EXPOSE 8000

# The command to run when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]