"""
声明收集的个人信息集提取
"""
from utils.common.utils import get_PI, get_most_similar_pi
import jionlp as jio

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


def extract_DPIS(sentence: str, ans):

    # 提取句子关键词
    keywords = jio.keyphrase.extract_keyphrase(sentence)
    for keyword in keywords:
        flag_equal_texts, ans = judge_info_equal_text(keyword, ans)
