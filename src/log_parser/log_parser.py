import os
import re

class LogParser:
    """
    A dedicated class for reading and parsing raw log files to extract
    meaningful security events.
    """
    def __init__(self, keywords):
        """
        Initializes the parser with a list of keywords to filter for.
        
        Args:
            keywords (list): A list of strings. Lines containing any of these keywords 
                             (case-insensitive) will be considered an "event".
        """
        print("Log Parser Initialized.")
        if not keywords:
            raise ValueError("Cannot initialize LogParser with an empty list of keywords.")
            
        # Compile all keywords into a single, efficient regular expression
        # This allows it to check for all keywords in one pass.
        self.keyword_regex = re.compile("|".join(keywords), re.IGNORECASE)
        print(f"Filtering for {len(keywords)} keywords.")

    def parse_log_file(self, log_file_path):
        """
        Reads a raw log file line by line and yields cleaned event messages.

        This method uses a generator (`yield`) to be memory-efficient, which is crucial
        for processing potentially gigabyte-sized log files without high RAM usage.
        
        Args:
            log_file_path (str): The full path to the raw log file.
        
        Yields:
            str: A single, cleaned event message string if a line matches a keyword.
        """
        if not os.path.exists(log_file_path):
            print(f"ERROR [LogParser]: Log file not found at '{log_file_path}'")
            return

        print(f"Parsing raw log file: {log_file_path}")
        with open(log_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    # If a line in the log file contains one of our keywords...
                    if self.keyword_regex.search(line):
                        # ...then it's an interesting event that we should analyze.
                        # We clean it by removing the typical syslog timestamp/header.
                        cleaned_line = re.sub(
                            r"^\w{3}\s+\d{1,2}\s+[\d:]{8}\s+[\w\.\-]+\s+[\w\d\-_\[\]]+:\s+", 
                            "", 
                            line.strip()
                        )
                        # We 'yield' the result, turning this function into a memory-efficient generator.
                        yield cleaned_line
                except Exception as e:
                    print(f"WARNING [LogParser]: Could not process line {line_num} in {log_file_path}. Error: {e}")

# This part allows you to test the parser on its own
if __name__ == '__main__':
    print("--- Testing LogParser as a standalone script ---")
    
    test_keywords = ["Failed password", "session opened"]
    dummy_log_file = "test_log.tmp"

    with open(dummy_log_file, "w") as f:
        f.write("Oct 10 14:35:10 my-server sshd[12345]: Failed password for invalid user 'admin'\n")
        f.write("Oct 10 14:35:12 my-server kernel: This is a normal, boring log line.\n")
        f.write("Oct 10 14:35:14 my-server sshd[9876]: session opened for user tejas\n")

    parser = LogParser(keywords=test_keywords)
    events = parser.parse_log_file(dummy_log_file)
    
    print("\nFound the following important events:")
    for event in events:
        print(f"  - '{event}'")
    
    os.remove(dummy_log_file)