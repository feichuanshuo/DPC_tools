import traceback

from loguru import logger

from utils.dynamic_detect.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from utils.dynamic_detect.algorithms.utils import Timer
from utils.dynamic_detect.algorithms.utils.q import Q


class QLearnAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(env, timesteps, timer, eps=0.8, **kwargs):
        try:
            t = Timer(timer)
            q_l = Q(env, t, eps=eps)
            q_l.learn(timesteps)
            return True
        except Exception as e:
            logger.error(f'Error: {e}')
            logger.error(f'Stack trace:, {traceback.format_exc()}')
            return False
