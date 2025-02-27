"""
声明收集的个人信息集提取
"""
from utils.common.pi_utils import get_PI, get_most_similar_pi
from utils.common.nlp_utils import seg_by_jieba


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


def judge_keyword_equal_text(text):
    """
    Determine whether PI appears directly in text
    """
    flag = 0
    for key in PI_keys:
        if key == text.lower():
            return True, key
    if not flag and len(text) <= 10:
        tkey = get_most_similar_pi(text, cos_distance_line)

        if tkey != '':
            return True, tkey

    return False, ''


def extract_DPIS(sentence: str, ans):

    # 分词
    words = seg_by_jieba(sentence,remove_stopwords=True)
    for word in words:
        flag_equal_texts, key = judge_keyword_equal_text(word)
        if flag_equal_texts:
            ans = add_ans(ans,key,word)

if __name__ == '__main__':
    ans = {}
    extract_DPIS('同时，我们会根据监管机构要求收集您的个人身份信息，以及办理网上开户业务法律法规所规定的信息， 包括您的姓名、性别、民族、国籍、出生日期、证件类型、证件号码、证件签发机关、证件有效期、有效身份证件的彩色照片、个人生物识别信息、开户声明视频、联系电话、联系地址（常住地址）、职业、学历、银行卡号信息、税收居民身份、财务状况、收入来源、诚信信息、债务情况、投资相关的学习、工作经历和投资风险信息、风险偏好及可承受的损失、投资期限、品种、期望收益投资目标信息、实际控制投资者的自然人和交易的实际受益人、法律法规、行业自律规则规定的投资者准入要求的相关信息',ans)
    print(ans)