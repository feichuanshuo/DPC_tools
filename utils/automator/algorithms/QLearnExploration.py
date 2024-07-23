from utils.automator.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from utils.automator.algorithms.utils import Timer
from utils.automator.algorithms.utils.q import Q


class QLearnAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(env, timesteps, timer, eps=0.8, **kwargs):
        # try:
            t = Timer(timer)
            q_l = Q(env, t, eps=eps)
            q_l.learn(timesteps)
            return True
        # except Exception as e:
        #     print(e)
        #     return False
