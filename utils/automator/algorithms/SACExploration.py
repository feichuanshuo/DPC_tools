import os
import traceback

from stable_baselines3.sac.policies import MlpPolicy
from stable_baselines3 import SAC
from utils.automator.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from loguru import logger
from utils.automator.algorithms.utils.wrapper import TimeFeatureWrapper
from configuration import sac_model_dir


class SACAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, timesteps, timer, save_policy=False, reload_policy=False,
                cycle=0, train_freq=5, target_update_interval=10, **kwargs):
        try:
            app_name = app.package.split('.')[-1]
            env = TimeFeatureWrapper(app)
            # Loading a previous policy and checking file existence
            if reload_policy and (os.path.isfile(f'{sac_model_dir}{os.sep}{app_name}.zip')):
                temp_dim = env.action_space.high[0]
                env.action_space.high[0] = env.env.ACTION_SPACE
                logger.info(f'Reloading Policy {app_name}.zip')
                model = SAC.load(f'{sac_model_dir}{os.sep}{app_name}', env)
                env.action_space.high[0] = temp_dim
            else:
                logger.info('Starting training from zero')
                model = SAC(MlpPolicy, env, verbose=1, train_freq=train_freq, target_update_interval=target_update_interval, device='cuda', buffer_size=10000)
            model.env.envs[0].check_activity()
            model.learn(total_timesteps=timesteps)
            # It will overwrite the previous policy
            if save_policy:
                logger.info('Saving Policy...')
                model.action_space.high[0] = model.env.envs[0].ACTION_SPACE
                model.save(f'{sac_model_dir}{os.sep}{app_name}')
            return True
        except Exception as e:
            logger.error(f'Error: {e}')
            logger.error(f'Stack trace:, {traceback.format_exc()}')
            return False

