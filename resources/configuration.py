import os

current_file_dir = os.path.dirname(os.path.abspath(__file__))

# PI
PI_path = os.path.join(current_file_dir, "personal_information.json")

# gui中的PI
ui_regex_path = os.path.join(current_file_dir, "ui_regex.txt")