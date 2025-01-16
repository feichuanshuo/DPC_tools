import re
from xml.etree import ElementTree as ET
from utils.common.segmentation import seg_by_jieba
from utils.common.utils import get_PI, get_ui_regex, get_most_similar_pi
from loguru import logger

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


def add_ans(ans, key, text):
    pi_type = PI[key]['pi_type']
    pi = PI[key]['pi']

    if pi_type not in ans.keys():
        ans[pi_type] = {
            pi: [text]
        }
    elif pi not in ans[pi_type].keys():
        ans[pi_type][pi] = [text]
    elif text not in ans[pi_type][pi]:
        ans[pi_type][pi].append(text)

    return ans


def judge_info_equal_text(text, ans):
    """
    Determine whether PI appears directly in text
    """
    flag = 0
    for key in PI_keys:
        if key == text.lower():
            flag = 1
            ans = add_ans(ans, key, text)
            break

    # If length <= 10, calculate the similarity
    if not flag and len(text) <= 10:
        tkey = get_most_similar_pi(text, cos_distance_line)

        if tkey != '':
            flag = 1
            ans = add_ans(ans, tkey, text)

    return flag, ans


def judge_info_in_texts(texts, ans):
    """
    正则匹配后，判断是否尝试收集个人信息
    :param texts: 正则匹配后的text
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
                ans = add_ans(ans, tkey, text)

    return ans


def extract_PI(xml):
    logger.info('开始提取个人信息')
    ans = {}
    tree = ET.fromstring(xml)

    for node in tree.iter():
        texts = []
        for key in node.attrib.keys():
            # Find all "text" or "hint" attributes, such as <TextView android:text="Gender:"/>
            if key.endswith('text') or key.endswith('hint'):
                try:
                    tmp_text = node.get(key)

                    chinese_model = re.compile(u'[\u4e00-\u9fa5]')
                    english_PI_model = ['email', 'e-mail', 'sim', 'imsi', 'imei', 'androidid', 'adid',
                                        'android sn', 'idfa', 'openudid', 'guid', 'wifi', 'wlan', 'wlan']

                    if chinese_model.search(tmp_text) or any(o in tmp_text.lower() for o in english_PI_model):
                        texts.extend(re.split("[，。；、\n]", tmp_text))
                except:
                    continue

        # 清洗数据
        texts = [t.replace(' ', '') for t in texts]
        texts = [t for t in texts if t != '']
        texts = [t.strip() for t in texts]
        texts = [t.lower() for t in texts]

        if not texts:
            continue

        for text in texts:
            # First determine whether PI appears directly, like <TextView text="ID card number">
            flag_equal_texts, ans = judge_info_equal_text(text, ans)

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
                    ans = judge_info_in_texts(texts_after_regex, ans)

    logger.success('提取个人信息完成')
    return ans


if __name__ == '__main__':
    with open("../../test0/screen_dump.xml", "r", encoding='utf-8') as f:
        xml = f.read()
    result = extract_PI(xml)
    print(result)
