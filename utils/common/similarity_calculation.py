import re

import hanlp
from configuration import benchmark_subtitles, subtitle_word_frequency_similarity_threshold, subtitle_semantic_similarity_threshold
import numpy as np

def get_sts_hanlp():
    """
    The hanlp model for calculating text semantic similarity
    "sts" stands for Semantic Textual Similarity
    """
    sts = hanlp.load(hanlp.pretrained.sts.STS_ELECTRA_BASE_ZH)
    return sts


sts = get_sts_hanlp()


def cos_dist(vec1, vec2):
    """
    Get the cosine similarity of two vectors
    """
    dist = float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))
    return dist


def get_word_vector_by_frequency(s1, s2):
    """
    Get the term-frequency vectors of s1 and s2
    获取 s1 和 s2 的项频率向量
    """
    # word segmentation
    # 先按标点符号分割，再逐字分割
    regEx = re.compile('\W')
    res = re.compile('([\u4e00-\u9fa5])')

    p1 = regEx.split(s1.lower())
    str1_list = []
    for tmp_str in p1:
        if res.split(tmp_str) is None:
            str1_list.append(tmp_str)
        else:
            ret = res.split(tmp_str)
            for ch in ret:
                str1_list.append(ch)

    p2 = regEx.split(s2.lower())
    str2_list = []
    for tmp_str in p2:
        if res.split(tmp_str) is None:
            str2_list.append(tmp_str)
        else:
            ret = res.split(tmp_str)
            for ch in ret:
                str2_list.append(ch)

    list_word1 = [w for w in str1_list if len(w.strip()) > 0]
    list_word2 = [w for w in str2_list if len(w.strip()) > 0]

    key_word = list(set(list_word1 + list_word2))

    word_vector1 = np.zeros(len(key_word))
    word_vector2 = np.zeros(len(key_word))

    # calculate the frequency
    for i in range(len(key_word)):
        for j in range(len(list_word1)):
            if key_word[i] == list_word1[j]:
                word_vector1[i] += 1
        for k in range(len(list_word2)):
            if key_word[i] == list_word2[k]:
                word_vector2[i] += 1

    return word_vector1, word_vector2


def similarity_by_word_frequency(s1: str, s2: str):
    """
    Get the similarity (term-frequency) between s1 and s2
    """
    v1, v2 = get_word_vector_by_frequency(s1, s2)
    return cos_dist(v1, v2)


def judge_privacy_category(target_subtitle):
    """
    Determine the privacy category for the target subtitle by calculating similarity
    """
    # preprocess the target subtitle, remove common but meaningless words
    # 预处理目标句子，去除常见但无意义的词
    target_subtitle = target_subtitle.replace('我们会', '')
    target_subtitle = target_subtitle.replace('我们', '')
    target_subtitle = target_subtitle.replace('您的', '')
    target_subtitle = target_subtitle.replace('你的', '')
    target_subtitle = target_subtitle.replace('您', '')
    target_subtitle = target_subtitle.replace('你', '')
    target_subtitle = target_subtitle.replace('如何', '')
    target_subtitle = target_subtitle.replace('隐私政策', '')
    target_subtitle = target_subtitle.replace('个人信息', '信息')

    if len(target_subtitle) > 25:
        # For those with a length greater than 25, it is considered not to be a subtitle.
        return None

    else:
        if '无需征得' in target_subtitle or '征得同意的例外' in target_subtitle or '响应上述请求' in target_subtitle or '无需事先征得' in target_subtitle:
            return 0

        if target_subtitle == '信息保护及隐私政策':
            return None

        for privacy_category, benchmark_list in benchmark_subtitles.items():
            for el in benchmark_list:
                # Calculate word frequency similarity between target_subtitle and benchmark_subtitle
                if target_subtitle == el or similarity_by_word_frequency(target_subtitle,
                                                                         el) > subtitle_word_frequency_similarity_threshold:
                    return privacy_category

        # Calculate semantic similarity between target_subtitle and benchmark_subtitle using hanlp
        # 使用hanlp计算target_subtitle和benchmark_subtitle之间的语义相似度
        similarity_list = []
        privacy_category_index = []
        benchmark_subtitle_list = []
        for privacy_category, benchmark_list in benchmark_subtitles.items():
            for el in benchmark_list:
                similarity_list.append((target_subtitle, el))
                privacy_category_index.append(privacy_category)
                benchmark_subtitle_list.append(el)

        similarity_results = sts(similarity_list)
        max_sim = max(similarity_results)

        if max_sim > subtitle_semantic_similarity_threshold:
            # print(benchmark_subtitle_list[similarity_results.index(max_sim)])
            # print(max_sim)
            return privacy_category_index[similarity_results.index(max_sim)]

    return None