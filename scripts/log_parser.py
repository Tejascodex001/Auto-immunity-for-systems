# convert_mordor.py (Corrected Version)

import json
import os
import glob

# --- Configuration ---
MORDORDATA_SOURCE_DIR = "/home/tejas/Projects/AIS/data/dataset/" # Using the path from your log
OUTPUT_JSONL_FILE = "/home/tejas/Projects/AIS/data/mordor_finetuning.jsonl"

# --- Main Conversion Script ---
def process_mordor_file(filepath, outfile_handle):
    """
    Reads a single Mordor JSON file (which is actually in JSON Lines format),
    processes each event, and writes it to the output .jsonl file.
    """
    print(f"  > Processing file: {os.path.basename(filepath)}")
    processed_count = 0
    
    # --- THIS IS THE CORRECTED LOGIC ---
    # We now open the file and read it LINE BY LINE.
    with open(filepath, 'r') as infile:
        for line in infile:
            # Skip any empty lines
            if not line.strip():
                continue
            
            try:
                # Each line is its own JSON object
                event = json.loads(line)

                # --- The prompt engineering logic remains the same ---
                channel = event.get('Channel')
                provider = event.get('Provider', {}).get('Name')
                event_id = event.get('EventID')
                computer = event.get('Computer')
                event_data = event.get('EventData', {})
                
                instruction = (
                    f"Analyze the following Windows security event:\n"
                    f"- Source Computer: {computer}\n"
                    f"- Log Channel: {channel}\n"
                    f"- Event Provider: {provider}\n"
                    f"- Event ID: {event_id}\n"
                    f"- Event Data: {json.dumps(event_data)}"
                )

                threat_type = "Suspicious Host Activity"
                if event_id == 4688:
                    process_name = event_data.get('NewProcessName', '').split('\\')[-1]
                    if process_name.lower() in ['powershell.exe', 'cmd.exe', 'wmic.exe']:
                        threat_type = "Suspicious Process Creation"
                
                output = {
                    "summary": f"A '{threat_type}' event (ID {event_id}) was detected on host {computer}.",
                    "threat_type": threat_type,
                    "host_name": computer,
                    "event_id": event_id,
                    "risk_level": "Medium",
                }

                record = {
                    "messages": [
                        {"role": "system", "content": "You are a host-based security analyst..."},
                        {"role": "user", "content": instruction},
                        {"role": "assistant", "content": json.dumps(output)}
                    ]
                }
                outfile_handle.write(json.dumps(record) + '\n')
                processed_count += 1

            except json.JSONDecodeError:
                # This might catch a malformed line within a file
                print(f"    - WARNING: Could not decode a JSON line in the file. Skipping line.")
                continue
            except Exception as e:
                print(f"    - An unexpected error occurred while processing a line: {e}")
                continue
    # --- END OF CORRECTED LOGIC ---
            
    return processed_count


# --- The rest of the script is unchanged ---
if __name__ == "__main__":
    print(f"--- Starting Mordor Dataset Conversion ---")
    print(f"Source directory: {MORDORDATA_SOURCE_DIR}")

    all_json_files = glob.glob(os.path.join(MORDORDATA_SOURCE_DIR, '**/*.json'), recursive=True)

    if not all_json_files:
        print("\n❌ ERROR: No .json files found in the source directory. Please check your path.")
    else:
        print(f"Found {len(all_json_files)} JSON files to process.")
        total_events_processed = 0
        
        with open(OUTPUT_JSONL_FILE, 'w') as outfile:
            for filepath in all_json_files:
                total_events_processed += process_mordor_file(filepath, outfile)
        
        if total_events_processed > 0:
            print(f"\n✅ Conversion complete! Processed {total_events_processed:,} events.")
            print(f"All events have been saved to '{OUTPUT_JSONL_FILE}'.")
        else:
            print("\nNo events were processed. Please check the content of your JSON files.")