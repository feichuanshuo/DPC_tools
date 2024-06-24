import os

current_file_dir = os.path.dirname(os.path.abspath(__file__))

# PI
PI_path = os.path.join(current_file_dir, "personal_information.json")

# gui中的PI
ui_regex_path = os.path.join(current_file_dir, "ui_regex.txt")

# stopwords
stopwords_path = os.path.join(current_file_dir, "stopwords.txt")

# word2vec configurations
w2v_model_path = os.path.join(current_file_dir, "../utils/common/word2vec/model/w2v.model")
w2v_vector_path = os.path.join(current_file_dir, "../utils/common/word2vec/model/wv.vector")

# adb路径
adb_path = os.path.join(current_file_dir, "windows/adb.exe")