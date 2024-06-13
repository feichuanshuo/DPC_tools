import numpy as np
from gensim.models import Word2Vec
from gensim.models import KeyedVectors

from resources.configuration import w2v_vector_path, w2v_model_path

# load the trained vectors
wv = KeyedVectors.load_word2vec_format(w2v_vector_path)


def get_wv(word: str):
    """
    Get the vector for a target word
    :param word: string, the target word
    :return: <class 'numpy.ndarray'>, the vector representing the word
    """
    try:
        return wv[word]
    except:
        # for Out-of-Vocabulary, generate a random vector
        # 对于Out-of-Vocabulary，生成一个随机向量
        word_vec = np.random.random(100)
        return word_vec


def get_wvs(words: list):
    """
    Get vectors of a target word list
    :param words: list, the target word list
    :return: list, the vector list representing the word list
    """
    wvs = []
    for word in words:
        try:
            wvs.append(get_wv(word))
        except:
            wvs.append(np.random.random(100))
            continue
    return wvs


if __name__ == '__main__':
    # load word2vec model
    model = Word2Vec.load(w2v_model_path)

    # load vectors
    vector = KeyedVectors.load_word2vec_format(w2v_vector_path)

    # Get the word vector of a word
    print(model.wv['手机号码'])
    print(vector['手机号码'])
