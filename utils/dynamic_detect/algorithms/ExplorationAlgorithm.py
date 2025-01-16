import abc


class ExplorationAlgorithm:
    __metaclass__ = abc.ABCMeta

    @staticmethod
    @abc.abstractmethod
    def explore(env, timesteps, timer, **kwargs):
        raise NotImplementedError()