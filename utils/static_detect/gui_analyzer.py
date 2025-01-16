import os
import re
import subprocess
from xml.etree import ElementTree

from utils.common.segmentation import seg_by_jieba
from utils.common.utils import get_PI, get_ui_regex, get_most_similar_pi
from configuration import apktool_path, apk_decompile_save_dir

# 判断两个词语是否相似的阈值，1为完全相同，使用余弦相似度
cos_distance_line = 0.9

PI = get_PI()
"""
格式如下:
{
    '姓名': {'pi_type': 'basic PI', 'pi': 'name'},  # 姓名
}
"""
PI_keys = list(PI.keys())
ui_regex = get_ui_regex()
"""
格式如下:
[[收集(你的|您的|你|您|的)?以下信息[:：\n](.+),2]]
"""

def open_xml(tmp_path) -> list:
    """
    Get XML file path list (for decompiled APK file)
    """
    xmllist = []
    for home, dirs, files in os.walk(tmp_path):
        for filename in files:
            if '.xml' in filename:
                xmllist.append(os.path.join(home, filename))

    return xmllist


def open_layout_xml(tmp_path) -> list:
    """
    Get layout xml file path list
    """
    layout_xml_list = []
    layout_paths = []
    res_path = os.path.join(tmp_path, 'res')

    dirs = os.listdir(res_path)
    for d in dirs:
        if d.startswith('layout'):
            layout_paths.append(os.path.join(res_path, d))

    for l in layout_paths:
        for home, dirs, files in os.walk(l):
            for filename in files:
                if '.xml' in filename:
                    layout_xml_list.append(os.path.join(home, filename))

    return layout_xml_list


def open_strings_xml(xml_path):
    """
    Find the string.xml file and parse it
    """
    strings_xml_path = []
    strings_ids_and_values = {}

    for p in xml_path:
        if p.endswith('values\\strings.xml') or p.endswith('values-zh\\strings.xml') or p.endswith(
                'values-zh-rCN\\strings.xml'):
            strings_xml_path.append(p)

    for p in strings_xml_path:
        try:
            with open(p, encoding="utf-8") as f:
                data = f.read()
        except Exception as e:
            print('{}: Read file error: {}'.format(p, e))
            continue
        xml = ElementTree.fromstring(data)

        # Traverse all xml nodes
        for node in xml.iter('string'):
            string_id = node.attrib.get('name')
            string_value = node.text
            if string_id in strings_ids_and_values.keys():
                strings_ids_and_values[string_id].append(string_value)
            else:
                strings_ids_and_values[string_id] = []
                strings_ids_and_values[string_id].append(string_value)

    return strings_ids_and_values


def add_ans(ans, key, node):
    if isinstance(node, str):
        node_string = 'in_string_xml,value={}'.format(node)
    else:
        node_string = ElementTree.tostring(node, encoding='unicode').strip()

    pi_type = PI[key]['pi_type']
    pi = PI[key]['pi']

    if pi_type not in ans.keys():
        ans[pi_type] = {
            pi: [node_string]
        }
    elif pi not in ans[pi_type].keys():
        ans[pi_type][pi] = [node_string]
    elif node_string not in ans[pi_type][pi]:
        ans[pi_type][pi].append(node_string)

    return ans


def judge_strings_xml(strings_ids_and_values, ans):
    """
    Determine whether the string in strings.xml tries to collect pi
    """
    texts = []

    values = []
    for v in strings_ids_and_values.values():
        values.extend(v)
    values = list(set(values))

    for text in values:
        chinese_model = re.compile(u'[\u4e00-\u9fa5]')
        english_PI_model = ['email', 'e-mail', 'iccid', 'sim', 'imei', 'imsi', 'androidid', 'adid', 'android sn',
                            'idfa', 'openudid', 'guid', 'wi-fi', 'wifi', 'wlan', 'nfc', 'dna']
        try:
            if chinese_model.search(text) or any(o in text.lower() for o in english_PI_model):
                texts.extend(re.split("[，。；、\n]", text))
        except:
            continue

    # clean
    texts = [t.replace(' ', '') for t in texts]
    texts = [t for t in texts if t != '']
    texts = [t.strip() for t in texts]
    texts = [t.lower() for t in texts]

    for text in texts:
        # First determine whether PI appears directly or a word similar to PI appears directly
        # For example, <TextView text="Phone number">
        flag_equal_texts, ans = judge_info_equal_text(text, text, ans)

        # Extract PI through regular expressions
        if not flag_equal_texts:
            flag_regex = 0
            texts_after_regex = []

            for r in ui_regex:
                regex_string = r[0]
                group_id = int(r[1])
                pattern = re.compile(regex_string)

                m = pattern.search(text)
                if m is not None:
                    texts_after_regex.append(m.group(group_id))
                    flag_regex = 1

            # When the regular match is successful, determine whether the matched result contains PI.
            if flag_regex:
                ans = judge_info_in_texts(texts_after_regex, text, ans)

    return ans


def judge_info_equal_text(text, node, ans):
    """
    Determine whether PI appears directly in text
    """
    flag = 0
    for key in PI_keys:
        if key == text.lower():
            flag = 1
            ans = add_ans(ans, key, node)
            break

    # If length <= 10, calculate the similarity
    if not flag and len(text) <= 10:
        tkey = get_most_similar_pi(text, cos_distance_line)

        if tkey != '':
            flag = 1
            ans = add_ans(ans, tkey, node)

    return flag, ans


def judge_info_in_texts(texts, node, ans):
    """
    正则匹配后，判断是否尝试收集个人信息
    :param texts: 正则匹配后的text
    :param node: 节点
    :param ans: 原先的ans
    :return: 更新后的ans
    """
    for text in texts:
        # segmentation
        # 去除句子中的停用词、空格等符号，并返回一个句子包含的词表
        words = seg_by_jieba(text, lower=False, remove_stopwords=True)
        for word in words:
            tkey = get_most_similar_pi(word, cos_distance_line)
            if tkey != '':
                ans = add_ans(ans, tkey, node)

    return ans


def gui_analyzer(apk_path, ans):
    """
       Determine what PI the apk may collect (through GUI analysis)
       """

    # 获取文件名和扩展名
    (file, ext) = os.path.splitext(apk_path)
    # 获取目录路径和文件名
    (path, filename) = os.path.split(apk_path)

    # 反编译后获取文件夹名称
    filename = filename.rstrip(ext)
    tmp_path = os.path.join(apk_decompile_save_dir, filename, '')

    # 使用 apktool 反编译 apk 文件
    if not os.path.exists(tmp_path):
        print('Decompiling in progress...')
        subprocess.getoutput('java -jar ' + apktool_path + ' d ' + apk_path + ' -o ' + tmp_path + ' -s')
    else:
        print('It is already decompiled...')

    res_path = os.path.join(tmp_path, 'res')
    if not os.path.exists(res_path):
        print('{}-Fail to decompile the apk file by apktool'.format(apk_path))
        return None

    # 获取所有 xml 文件名的列表
    all_xml_file = open_xml(tmp_path)

    # 解析strings.xml
    strings_ids_and_values = open_strings_xml(all_xml_file)

    # 获取布局文件名列表
    layout_xml_file = open_layout_xml(tmp_path)

    # 确定 strings.xml 中的所有字符串
    ans = judge_strings_xml(strings_ids_and_values, ans)

    # 遍历所有布局 xml 文件

    for xml_name in layout_xml_file:
        try:
            with open(xml_name, encoding="utf-8") as f:
                data = f.read()
        except Exception:
            continue

        try:
            xml = ElementTree.fromstring(data)
        except Exception:
            continue

        for node in xml.iter():
            texts = []
            for key in node.attrib.keys():
                # Find all "text" or "hint" attributes, such as <TextView android:text="Gender:"/>
                if key.endswith('text') or key.endswith('hint'):
                    try:
                        tmp_text = node.get(key)

                        chinese_model = re.compile(u'[\u4e00-\u9fa5]')
                        english_PI_model = ['email', 'e-mail', 'sim', 'imsi', 'imei', 'androidid', 'adid',
                                            'android sn', 'idfa', 'openudid', 'guid', 'wifi', 'wlan', 'wlan']

                        if tmp_text.startswith('@string/'):
                            v = strings_ids_and_values[tmp_text[8:]]
                            if v is not None:
                                for vv in v:
                                    texts.extend(re.split("[，。；、\n]", vv))

                        elif chinese_model.search(tmp_text) or any(o in tmp_text.lower() for o in english_PI_model):
                            texts.extend(re.split("[，。；、\n]", tmp_text))
                    except:
                        continue

            # clean the texts
            texts = [t.replace(' ', '') for t in texts]
            texts = [t for t in texts if t != '']
            texts = [t.strip() for t in texts]
            texts = [t.lower() for t in texts]

            for text in texts:
                # First determine whether PI appears directly, like <TextView text="ID card number">
                flag_equal_texts, ans = judge_info_equal_text(text, node, ans)

                # Use regular expressions to match, and then extract PI after successful matching.
                if not flag_equal_texts:
                    flag_regex = 0
                    texts_after_regex = []

                    for r in ui_regex:
                        regex_string = r[0]
                        group_id = int(r[1])
                        pattern = re.compile(regex_string)

                        m = pattern.search(text)
                        if m is not None:
                            texts_after_regex.append(m.group(group_id))
                            flag_regex = 1

                    if flag_regex:
                        ans = judge_info_in_texts(texts_after_regex, node, ans)

    return ans