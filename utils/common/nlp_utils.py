import string

import hanlp
import jieba

from configuration import stopwords_path
from utils.common.pi_utils import get_PI

PI = get_PI()
"""
格式如下:
{
    '姓名': {'pi_type': 'basic PI', 'pi': 'name'},  # 姓名
}
"""
PI_keys = list(PI.keys())
jieba.load_userdict(PI_keys)

def get_stopwords() -> list:
    """
    Get the stopwords list
    """
    with open(stopwords_path, 'r', encoding='utf-8') as f:
        stopwords = f.read()
    stopwords = stopwords.split("\n")
    return stopwords


def seg_by_jieba(sentence, lower=True, remove_stopwords=False) -> list:
    """
    jieba segmentation for model training (without removing stopwords)
    :param sentence: target sentence
    """
    stopwords = get_stopwords()

    if lower:
        sentence = sentence.lower()

    tokens = jieba.cut(sentence)
    words = []
    for i in tokens:
        if remove_stopwords:
            if i not in stopwords and i != ' ' and i != '\t' and i != '\xa0':
                words.append(i)
        else:
            words.append(i)
    return words


def get_seg_hanlp():
    """
    分词
    """
    seg_hanlp = hanlp.load(hanlp.pretrained.tok.COARSE_ELECTRA_SMALL_ZH)
    return seg_hanlp

def get_pos_hanlp():
    """
    词性标注
    """
    pos_hanlp = hanlp.load(hanlp.pretrained.pos.CTB9_POS_ELECTRA_SMALL)
    return pos_hanlp