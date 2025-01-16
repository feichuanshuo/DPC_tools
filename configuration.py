import os

root_dir = os.path.dirname(os.path.abspath(__file__))

"""resources目录配置"""
resources_dir = os.path.join(root_dir, "resources")

# 第三方sdk规则
third_party_sdk_path = os.path.join(resources_dir, "sdk.json")

# policy_structure_parser 配置
paragraph_number_regex_path = os.path.join(resources_dir,
                                           "policy_structure_parser_resources/paragraph_number_regex.csv")
paragraph_numbers_path = os.path.join(resources_dir, "policy_structure_parser_resources/paragraph_numbers.txt")

# PI
PI_path = os.path.join(resources_dir, "personal_information.json")

# ui_regex
ui_regex_path = os.path.join(resources_dir, "ui_regex.txt")

# api与PI的映射文件
api_pi_path = os.path.join(resources_dir, "api.json")

# permission与PI的映射文件
permission_pi_path = os.path.join(resources_dir, "permission.json")

# stopwords
stopwords_path = os.path.join(resources_dir, "stopwords.txt")

# the benchmark subtitles
benchmark_subtitles = {1: ['适用范围'],
                       2: ['联系', '开发者信息', '运营者基本信息'],
                       3: ['未成年人信息保护', '处理未成年人信息', '处理儿童信息', '未成年人条款', '未成年人保护',
                           '青少年条款'],
                       4: ['管理信息', '权利', '访问信息', '查阅和修订', '更新和通知', '访问和控制信息', '自主管理',
                           '信息访问及管理', '政策更新', '修订'],
                       5: ['收集信息', '使用信息', '收集和使用信息', '信息存储', '存储期限', '保存及保护信息',
                           '信息安全', '保护信息安全', '提供的信息', '信息范围',
                           '信息安全事件处置', '个人敏感信息提示', '保护信息', '信息采集和使用'],
                       6: ['使用第三方SDK', '分享信息', '共享信息', '对外提供', '信息披露', '共享、转让、公开披露信息',
                           '数据使用过程中涉及合作方以及转移、公开信息',
                           '与第三方共享、对外提供信息', '可能从第三方间接获取信息', '合作伙伴与SDK',
                           '第三方数据处理及信息的公开披露', '第三方服务', '合作场景'],
                       7: ['信息在全球范围转移', '信息存储地域', '保存地域', '信息存储和交换', '信息保存及跨境传输']}

# 文本相似度计算的相似度阈值
subtitle_word_frequency_similarity_threshold = 0.9
subtitle_semantic_similarity_threshold = 0.95

# violation analyzer model 配置
bert_pc_model = os.path.join(resources_dir, "policy_analyzer_model/bert/PC")
bert_cr_model = os.path.join(resources_dir, "policy_analyzer_model/bert/CR")

# adb路径
adb_path = os.path.join(resources_dir, "adb/adb.exe")

# frida_server路径
frida_server_arm = os.path.join(resources_dir, "frida/hluda-server-arm64")
frida_server_x86 = os.path.join(resources_dir, "frida/hluda-server-x86")
apktool_path = os.path.join(resources_dir, "apktool_2.7.0.jar")


"""store目录配置"""
store_dir = os.path.join(root_dir, "store")
policy_analysis_result_dir = os.path.join(store_dir, "policy_analysis_result.json")
status_dir = os.path.join(store_dir, "status.json")
PI_result_dir = os.path.join(store_dir, "PI_result.json")
parsed_policy_dir = os.path.join(store_dir, "parsed_policy.json")
DPIS_dir = os.path.join(store_dir, "DPIS.json")
RPIS_dir = os.path.join(store_dir, "RPIS.json")

# 发生错误的app界面截图目录
error_screenshot_dir = os.path.join(store_dir, "error_screenshot.xml")

# SAC算法的模型保存目录
sac_model_dir = os.path.join(store_dir, "sac_model")

# apktool反编译保存目录
apk_decompile_save_dir = os.path.join(store_dir, "gui_analyzer_tmp")

"""utils目录配置"""
utils_dir = os.path.join(root_dir, "utils")
# word2vec 配置
w2v_model_path = os.path.join(utils_dir, "common/word2vec/model/w2v.model")
w2v_vector_path = os.path.join(utils_dir, "common/word2vec/model/wv.vector")

"""hook脚本路径"""
hook_script_path = os.path.join(root_dir, "hook_script/script.js")