import json
from utils.common.similarity_calculation import cos_dist
from utils.common.word2vec.use_w2v import get_wv
from configuration import ui_regex_path,PI_path

def get_ui_regex():
    """
    Returns a list of regular expressions of ui_regex (for extracting pi in gui text)
    """
    regex = []
    with open(ui_regex_path, "r", encoding="utf-8") as f:
        regex_list = f.read().split('\n')
    for r in regex_list:
        regex.append(r.split(';;'))
    return regex

def get_PI():
    with open(PI_path, "r",encoding="utf-8") as f:
        PI = json.load(f)

    return PI

def get_most_similar_pi(word, threshold):
    """
    Get the PI which is the most similar to the target word (the similarity must exceed the threshold, or return '')
    :param word: the target word, for example: "date of birth"
    :param threshold: the threshold for similarity calculation
    :return the most similar PI, for example: "birthday", if no PI exceeds the threshold, return ''
    """
    maxsim = 0
    tkey = ''
    PI = get_PI()
    PI_keys = list(PI.keys())

    for key in PI_keys:
        if key == word.lower():
            return key

    for key in PI_keys:
        try:
            s = cos_dist(get_wv(key), get_wv(word))
        except:
            continue

        if s >= threshold:
            if s > maxsim:
                maxsim = s
                tkey = key

    return tkey