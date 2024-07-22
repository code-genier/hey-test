"""
Action to preprocess training data for causal analysis
"""
# pylint: disable= unused-argument
from fawkes.action import FawkesAction

from runbooks.aiops.aiops_causal_graph.actions.lib.utils import load_timeseries_definitions


class LoadTimeseriesDefinitions(FawkesAction):
    """
    Class to preprocess timeseries data for model training
    """

    def do_run(self, **kwargs):
        """
        Fetch timeseries definitions.
        :param kwargs:
        :return: timeseries definitions as a list
        """
        path = kwargs.get("definitions_path")
        return load_timeseries_definitions(logger=self.logger, need_training_only=True, path=path)
