import hanlp
import jieba

from configuration import stopwords_path


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
    The hanlp model for segmentation
    """
    seg_hanlp = hanlp.load(hanlp.pretrained.tok.COARSE_ELECTRA_SMALL_ZH)
    return seg_hanlp
