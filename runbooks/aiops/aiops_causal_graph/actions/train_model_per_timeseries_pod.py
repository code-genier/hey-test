"""
Action to train a model for causal analysis
"""
import json
from datetime import datetime, timedelta, timezone

import pandas as pd

from fawkes.action import FawkesAction
from fawkes.api.model import FawkesModelClient
from fawkes.api.timeseries import FawkesTimeseriesClient
from fawkes.utils.time_utils import TimeUtils
from pyrca.applications.WardenAIOps.rca import RCAEngine

from runbooks.aiops.aiops_causal_graph.actions.lib.constants import (
    CAUSAL_TRAINING_LOOKBACK_WINDOW_MILLIS,
    NO_DATA_PREFIX,
    NOT_ENOUGH_DATA_PREFIX,
    CAUSAL_TRAINING_INITIAL_LOOKBACK_WINDOW_MILLIS,
)
from runbooks.aiops.aiops_causal_graph.actions.lib.data_source_client import DataSourceClient
from runbooks.aiops.aiops_causal_graph.actions.lib.utils import get_full_timeseries_name


class TrainModelPerTimeseriesPod(FawkesAction):
    """
    Class to train a model on the given timeseries & pod
    """

    def __init__(
        self, data_source_client: DataSourceClient, logger, config=None, action_service=None, client_config=None
    ):
        super().__init__(config, action_service, client_config)
        self._timeseries_api_client = FawkesTimeseriesClient(client_config)
        self._model_api_client = FawkesModelClient(client_config)
        self._data_source_client = data_source_client
        self._model = RCAEngine()
        self.logger = logger

    def do_run(self, timeseries, pod_or_cell_metadata):
        """
        Wrapper for do_run_main
        :param timeseries: timeseries definition parsed from YAML along with pod information
        :param pod_or_cell_metadata: pod or cell information
        :return: log full_timeseries_name in exception when any exception occurs during training
        """
        full_timeseries_name = get_full_timeseries_name(timeseries["name"], pod_or_cell_metadata["name"])
        try:
            end_ts = TimeUtils.get_current_time_in_millis()
            start_ts = end_ts - CAUSAL_TRAINING_INITIAL_LOOKBACK_WINDOW_MILLIS
            datapoints = self._data_source_client.get_data(
                start_ts=start_ts,
                end_ts=end_ts,
                query_template=timeseries["query"],
                pod_or_cell_metadata=pod_or_cell_metadata,
                identifier=timeseries.get("identifier"),
            )
            if len(datapoints) == 1:
                return [self.do_run_main(timeseries, pod_or_cell_metadata)]
            return [
                self.do_run_main(timeseries, pod_or_cell_metadata, scope=datapoint["scope"]) for datapoint in datapoints
            ]
        except Exception as exc:
            raise type(exc)(f"Failed to train for {full_timeseries_name}")

    def do_run_main(self, timeseries, pod_or_cell_metadata, scope=None):
        """
        Pull timeseries datapoints from argus and/or storage, then train and store the model
        :param timeseries: timeseries definition parsed from YAML along with pod information
        :param pod_or_cell_metadata: pod or cell information
        :return: void
        """
        full_timeseries_name = get_full_timeseries_name(timeseries["name"], pod_or_cell_metadata["name"])
        if scope:
            full_timeseries_name += f"_{scope}"
        self.logger.debug(f"Starting training for timeseries {full_timeseries_name}")
        previous_timeseries = self._timeseries_api_client.get(full_timeseries_name)
        end_timestamp = TimeUtils.get_current_time_in_millis()

        if previous_timeseries and timeseries["version"] == previous_timeseries["version"]:
            # if there are previous stored datapoints for this timeseries, then only update with most recent ones
            self.logger.debug(
                f'Found timeseries {full_timeseries_name} with {len(previous_timeseries["training_data"])} datapoints, '
                f'last dated at {TimeUtils.get_date_time_string(previous_timeseries["last_data_point_ts_millis"])}'
            )
            start_timestamp = previous_timeseries["last_data_point_ts_millis"]
            batches = TrainModelPerTimeseriesPod.get_time_batches(start_timestamp, end_timestamp)
            new_training_data = {}
            for batch_start, batch_end in batches:
                datapoints = self._data_source_client.get_data(
                    start_ts=batch_start,
                    end_ts=batch_end,
                    query_template=timeseries["query"],
                    pod_or_cell_metadata=pod_or_cell_metadata,
                    identifier=timeseries.get("identifier"),
                )
                if scope:
                    new_training_data.update(
                        next(filter(lambda d: d["scope"] == scope, datapoints), {"data": {}}).get("data")
                    )
                elif len(datapoints) > 0:
                    new_training_data.update(datapoints[0].get("data"))

            new_timeseries_payload = {
                "version": timeseries["version"],
                "training_data": new_training_data,
                "last_data_point_ts_millis": max(new_training_data.keys())
                if new_training_data
                else previous_timeseries["last_data_point_ts_millis"],
                "expiry": True,
                "expiry_ts_millis": end_timestamp - CAUSAL_TRAINING_LOOKBACK_WINDOW_MILLIS,
            }
            self.logger.debug(
                f'Patching timeseries {full_timeseries_name} with {len(new_timeseries_payload["training_data"])} '
                f"datapoints, last dated at "
                f'{TimeUtils.get_date_time_string(new_timeseries_payload["last_data_point_ts_millis"])} '
            )
            full_timeseries_payload = self._timeseries_api_client.patch(
                full_timeseries_name, json.dumps(new_timeseries_payload)
            )
            full_training_data = {int(k): v for k, v in full_timeseries_payload["training_data"].items()}
        else:
            self.logger.debug(f"New timeseries is found, or version change is detected for {full_timeseries_name}")
            # if there are no timeseries under this name, then pull down full 30 days worth of datapoints for training
            # using batches of 1 day
            start_timestamp = end_timestamp - CAUSAL_TRAINING_LOOKBACK_WINDOW_MILLIS

            # get batch timestamps
            batches = TrainModelPerTimeseriesPod.get_time_batches(start_timestamp, end_timestamp)
            full_training_data = {}
            for batch_start, batch_end in batches:
                datapoints = self._data_source_client.get_data(
                    start_ts=batch_start,
                    end_ts=batch_end,
                    query_template=timeseries["query"],
                    pod_or_cell_metadata=pod_or_cell_metadata,
                    identifier=timeseries.get("identifier"),
                )
                if scope:
                    full_training_data.update(
                        next(filter(lambda d: d["scope"] == scope, datapoints), {"data": {}}).get("data")
                    )
                elif len(datapoints) > 0:
                    full_training_data.update(datapoints[0].get("data"))

            if not full_training_data:
                self.logger.debug(f"No datapoints can be found for training for timeseries {full_timeseries_name}")
                return f"{NO_DATA_PREFIX}{full_timeseries_name}"

            # create a new timeseries and store its training data
            new_timeseries_payload = {
                "name": full_timeseries_name,
                "version": timeseries["version"],
                "training_data": full_training_data,
                "last_data_point_ts_millis": max(full_training_data.keys()),
            }
            self._timeseries_api_client.create(json.dumps(new_timeseries_payload))

        if len(full_training_data) < 5000:
            self.logger.debug(
                f"Not enough datapoints ({len(full_training_data)}) can be found for training for timeseries "
                f"{full_timeseries_name}"
            )
            return f"{NOT_ENOUGH_DATA_PREFIX}{full_timeseries_name}"

        # pass data into model for training, then store the trained model
        self.logger.debug(f"Training on timeseries {full_timeseries_name} with {len(full_training_data)} datapoints")
        dataframe = pd.DataFrame(list(full_training_data.items()), columns=["timestamp", full_timeseries_name])
        dataframe = dataframe.set_index("timestamp")
        dict_model = self._model.train_detector(dataframe)[full_timeseries_name].to_dict()
        model = {
            "name": full_timeseries_name,
            "version": timeseries["version"],
            "model": dict_model,
            "last_model_train_ts_millis": TimeUtils.get_current_time_in_millis(),
        }
        self._model_api_client.create(json.dumps(model))
        self.logger.debug(f"Completed training for timeseries {full_timeseries_name}")
        return full_timeseries_name

    @staticmethod
    def get_time_batches(start_timestamp_millis, end_timestamp_millis):
        """
        Get batched for argus query
        :param start_timestamp_millis: start batch time
        :param end_timestamp_millis: End batch time
        :return: list of batches
        """
        temp_start = start_timestamp_millis
        batches = []
        while temp_start < end_timestamp_millis:
            next_day = datetime.utcfromtimestamp(temp_start / 1000).replace(
                microsecond=0, second=0, minute=0, hour=0
            ) + timedelta(days=1)
            temp_end = int(next_day.replace(tzinfo=timezone.utc).timestamp() * 1000)
            temp_end = min(end_timestamp_millis, temp_end)
            batches.append((temp_start, temp_end))
            temp_start = temp_end
        return batches


# keeping for testing
if __name__ == "__main__":
    timeseries_test = {
        "name": "thread_count_top_10_1p",
        "label": "Thread-Count-top-10-avg",
        "team": "CASP",
        "version": 1,
        "source": "argus",
        "type": "metric",
        "training_frequency": "daily",
        "training_class": "StatsDetector",
        "query": "AVERAGE(HIGHEST({start}:{end}:core.{kingdom}.{superpod}.{pod}:java-lang_type-Threading"
        ".ThreadCount{{device={pod}[-|-s]app*-*,site=pri}}:avg:1m-max,#10#,#max#))",
    }
    pod = {
        "datacenter": "phx",
        "name": "na68",
        "superpod": "sp4",
        "functional_domain": None,
        "environment": "production",
    }
    # TrainModelPerTimeseriesPod().do_run(timeseries_test, pod)
    print(TrainModelPerTimeseriesPod.get_time_batches(1672466668452, 1675059848000))
