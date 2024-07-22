"""
Action for post-processing
"""
from fawkes.constants import FAWKES_AUTH_ENDPOINT, FAWKES_ST2_API_ENDPOINT
from fawkes.rca.fawkes_ica_action import FawkesICAAction
from fawkes.rca.ica_digest import IcaDigest, ICAOrgImpacts
from st2client.client import Client
from st2client.models import Execution

from runbooks.aiops.aiops_causal_graph.actions.lib.constants import ENV_FALCON
from runbooks.aiops.aiops_causal_graph.actions.lib.utils import get_duration_in_minutes


class PostPredictionProcessing(FawkesICAAction):
    """
    Class for post-processing
    """

    def __init__(self, config=None, action_service=None, client_config=None):
        super().__init__(config, action_service, client_config)
        self.ica_digest = IcaDigest("Causal Graph Details", "ICA", "causal-graph", "Causal Graph")
        # setup for client for action executions
        self.client = Client(auth_url=FAWKES_AUTH_ENDPOINT, api_url=FAWKES_ST2_API_ENDPOINT)

    def execute_ica(self, **kwargs):
        """
        Execute ica
        :param kwargs:
        :return: str
        """
        # check for service to run static swimlanes for those metrics
        self.execute_ica_swimlanes(kwargs)
        for timeseries in kwargs["anomalous_timeseries"]:
            if timeseries["name"].startswith("pod_capacity_1p"):
                min_value, max_value, duration_in_min = self.get_anomaly_details_for_recommendations(timeseries)
                self.ica_digest.recommendations.append(
                    f"Core app capacity has been reduced to {min_value}-{max_value}% for {duration_in_min} minutes"
                )
                self.ica_digest.slack_recommendations.append(
                    f"Core app capacity has been reduced to {min_value}-{max_value}% for {duration_in_min} minutes"
                )

            if timeseries["name"].startswith("login_success_count_1p") or timeseries["name"].startswith(
                "login_success_count_falcon"
            ):
                min_value, max_value, duration_in_min = self.get_anomaly_details_for_recommendations(timeseries)
                self.ica_digest.recommendations.append(
                    f"Core app successful logins has been reduced to {min_value}-{max_value}% "
                    f"for {duration_in_min} minutes. Pls check for Service Disruption"
                )
                self.ica_digest.slack_recommendations.append(
                    f"Core app successful logins has been reduced to {min_value}-{max_value}% "
                    f"for {duration_in_min} minutes. *Pls check for Service Disruption*"
                )

            if timeseries["name"].startswith("top_10_avg_cpu_1p"):
                self.execute_actions(
                    action_name="aiops_fawkes_ica.jfr_swimlane_action",
                    parameters={
                        "env_type": kwargs.get("env_type"),
                        "metadata": kwargs.get("metadata"),
                        "execution_id": kwargs.get("execution_id"),
                        "start_ts": kwargs.get("start_ts"),
                        "end_ts": kwargs.get("end_ts"),
                    },
                )

            if timeseries["name"].startswith("conn_pool_waits"):
                hosts = timeseries["hosts"]
                self.ica_digest.recommendations.append(
                    f"{len(hosts)} hosts are impacted by conn pool waits: " f"{', '.join(hosts)}"
                )
                self.ica_digest.slack_recommendations.append(
                    f"{len(hosts)} hosts are impacted by conn pool waits: "
                    f"{', '.join(hosts[:5])}{' & others' if len(hosts) > 5 else ''}"
                )

            # check if only one rac node and that is disabled
            if timeseries["name"].startswith("conn_pool_node_disabled_1p"):
                racs = kwargs.get("metadata").get("racs", [])
                rac_disabled = timeseries.get("scope")
                if len(racs) == 1 and rac_disabled and racs[0] == int(rac_disabled):
                    self.ica_digest.recommendations.append(
                        "There is only 1 rac node available on this pod, which is disabled. This could lead to Service "
                        "Disruption"
                    )
                    self.ica_digest.slack_recommendations.append(
                        "There is only `1` rac node available on this pod, which is disabled."
                        "This could lead to *Service Disruption* "
                    )

        conn_pool_single_org_timeseries = next(
            filter(lambda t: t["name"].startswith("conn_pool_single_org"), kwargs["anomalous_timeseries"]), None
        )
        # add to ICA digest
        if conn_pool_single_org_timeseries:
            self.ica_digest.org_impact.append(
                ICAOrgImpacts(
                    signal_type="connection_pool",
                    single_org_impact=True,
                    org_ids=[conn_pool_single_org_timeseries.get("org_id")],
                )
            )

        # run info swimlane, trigger only if its is not triggered in main ICA Action
        if not kwargs.get("custom_params", {}).get("trigger_info_swimlanes") and not kwargs.get(
            "custom_params", {}
        ).get("trigger_all_swimlanes"):
            self.execute_actions(
                action_name="aiops_fawkes_ica.info_swimlane_action",
                parameters={
                    "env_type": kwargs.get("env_type"),
                    "metadata": kwargs.get("metadata"),
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "org_id_for_single_org_impact": conn_pool_single_org_timeseries.get("org_id")
                    if conn_pool_single_org_timeseries
                    else None,
                    "anomalous_timeseries": kwargs.get("anomalous_timeseries"),
                },
            )

        impacted_services = [service for service in kwargs["impacted_services"] if service]
        if impacted_services:
            text = f'Impacted service(s): {", ".join(impacted_services)} - refer to thread for more details'
            self.ica_digest.recommendations.append(text)
            self.ica_digest.slack_recommendations.append(text)

        self.merge_digest(self.ica_digest)
        return [self.ica_digest]

    @staticmethod
    def get_anomaly_details_for_recommendations(timeseries):
        """
        Return the range and duration of anomalous values for the given timeseries
        :param timeseries: timeseries object with anomaly info
        :return:
        """
        min_value = min(map(lambda t: t["value"], timeseries["anomaly_info"]["anomalies"]))
        max_value = max(map(lambda t: t["value"], timeseries["anomaly_info"]["anomalies"]))
        start_time = min(map(lambda t: t["timestamp"], timeseries["anomaly_info"]["anomalies"]))
        end_time = max(map(lambda t: t["timestamp"], timeseries["anomaly_info"]["anomalies"]))
        duration_in_min = get_duration_in_minutes(start_time, end_time)
        return min_value, max_value, duration_in_min

    def execute_actions(self, action_name, parameters):
        """
        Execute actions
        :param action_name: Name of action
        :param parameters: Param to pass
        :return:
        """
        self.client.executions.create(Execution(action=action_name, parameters=parameters))

    def execute_ica_swimlanes(self, kwargs):
        """
        Run other ica swimlanes
        """
        services = kwargs.get("impacted_services")
        env = kwargs.get("env_type")
        custom_params = kwargs.get("custom_params", {})

        # run core app swimlane, trigger only if its is not triggered in main ICA Action
        if not custom_params.get("trigger_core_app_swimlanes"):
            self.logger.info("Triggering core app swimlanes")
            self.execute_actions(
                action_name="aiops_fawkes_ica.core_app_action",
                parameters={
                    "env_type": kwargs.get("env_type"),
                    "metadata": kwargs.get("metadata"),
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "trigger_source": kwargs.get("custom_params", {}).get("trigger_source"),
                    "incident_detection_signal": kwargs.get("custom_params", {}).get("incident_detection_signal"),
                    "record_id": kwargs.get("custom_params", {}).get("record_id"),
                    "incident_object_guid": kwargs.get("custom_params", {}).get("incident_object_guid"),
                    "include_casp_actions": kwargs.get("custom_params", {}).get("trigger_casp_core_app_swimlanes"),
                    "perform_causation": "Core App" in services,
                    "is_custom_time": kwargs.get("is_custom_time"),
                    "anomalous_timeseries": kwargs.get("anomalous_timeseries"),
                },
            )

        # run search swimlane, trigger only if its is not triggered in main ICA Action
        if not kwargs.get("is_custom_time") and not custom_params.get("trigger_search_swimlanes"):
            self.logger.info("Triggering search swimlanes")
            self.execute_actions(
                action_name="search_ica.search_swimlane",
                parameters={
                    "env_type": kwargs.get("env_type"),
                    "metadata": kwargs.get("metadata"),
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "perform_causation": ("Search" in services)
                    or (kwargs.get("custom_params", {}).get("trigger_source") == "gus_lap_case"),
                    "trigger_source": kwargs.get("custom_params", {}).get("trigger_source"),
                },
            )

        # run DB swimlane, trigger only if its is not triggered in main ICA Action
        if not custom_params.get("trigger_db_swimlanes"):
            self.logger.info("Triggering DB swimlane")
            self.execute_actions(
                action_name="cdbp_db_rca.db_detection_workflow",
                parameters={
                    "pod": kwargs.get("metadata")["cell"] if env == ENV_FALCON else kwargs.get("metadata")["pod"],
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "post_to_slack": True,
                    "workflow_trigger": True,
                    "record_id": kwargs.get("custom_params", {}).get("record_id"),
                    "post_id": kwargs.get("custom_params", {}).get("post_id"),
                    "trigger_source": kwargs.get("custom_params", {}).get("trigger_source"),
                    "perform_causation": True,
                },
            )

        # run Conn Pool swimlane, trigger only if its is not triggered in main ICA Action and if conn pool is impacted
        if not custom_params.get("trigger_conn_pool_swimlanes"):
            self.logger.info("Triggering Conn Pool swimlane")
            self.execute_actions(
                action_name="aiops_fawkes_ica.conn_pool_action",
                parameters={
                    "env_type": kwargs.get("env_type"),
                    "metadata": kwargs.get("metadata"),
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "trigger_source": kwargs.get("custom_params", {}).get("trigger_source"),
                    "incident_detection_signal": kwargs.get("custom_params", {}).get("incident_detection_signal"),
                    "record_id": kwargs.get("custom_params", {}).get("record_id"),
                    "incident_object_guid": kwargs.get("custom_params", {}).get("incident_object_guid"),
                    "perform_causation": "Conn Pool" in services,
                    "is_custom_time": kwargs.get("is_custom_time"),
                    "anomalous_timeseries": kwargs.get("anomalous_timeseries"),
                },
            )

        # run release swimlane
        if not custom_params.get("trigger_release_swimlanes"):
            self.logger.info("Triggering Release Swimlane")
            self.execute_actions(
                action_name="aiops_fawkes_ica.release_swimlane_action",
                parameters={
                    "env_type": kwargs.get("env_type"),
                    "metadata": kwargs.get("metadata"),
                    "execution_id": kwargs.get("execution_id"),
                    "start_ts": kwargs.get("start_ts"),
                    "end_ts": kwargs.get("end_ts"),
                    "anomalous_timeseries": kwargs.get("anomalous_timeseries"),
                },
            )
