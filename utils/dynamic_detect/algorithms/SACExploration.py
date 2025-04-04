import os
import traceback

from stable_baselines3.sac.policies import MlpPolicy
from stable_baselines3 import SAC
from utils.dynamic_detect.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from loguru import logger
from utils.dynamic_detect.algorithms.utils.wrapper import TimeFeatureWrapper
from utils.dynamic_detect.algorithms.utils.TimerCallback import TimerCallback
from configuration import sac_model_dir


class SACAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, timesteps, timer, save_policy=False, reload_policy=False,
                cycle=0, train_freq=5, target_update_interval=10, **kwargs):
        try:
            # app_name = app.package.split('.')[-1]
            env = TimeFeatureWrapper(app)
            # Loading a previous policy and checking file existence
            if reload_policy and (os.path.isfile(f'{sac_model_dir}.zip')):
                temp_dim = env.action_space.high[0]
                env.action_space.high[0] = env.env.ACTION_SPACE
                logger.info(f'Reloading Policy sac_model.zip')
                model = SAC.load(f'{sac_model_dir}', env)
                env.action_space.high[0] = temp_dim
            else:
                logger.info('Starting training from zero')
                model = SAC(MlpPolicy, env, verbose=1, train_freq=train_freq, target_update_interval=target_update_interval, device='cuda', buffer_size=10000)
            # model.env.envs[0].check_activity()
            model.env.envs[0].unwrapped.check_activity()
            callback = TimerCallback(timer=timer, app=app)
            model.learn(total_timesteps=timesteps, callback=callback)
            # It will overwrite the previous policy
            if save_policy:
                logger.info('Saving Policy...')
                model.action_space.high[0] = model.env.envs[0].ACTION_SPACE
                model.save(f'{sac_model_dir}')
            return True
        except Exception as e:
            logger.error(f'Error: {e}')
            logger.error(f'Stack trace:, {traceback.format_exc()}')
            return False

