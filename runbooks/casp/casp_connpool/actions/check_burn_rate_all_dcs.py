# pylint: disable=invalid-name,too-many-locals,broad-except,too-many-arguments
"""
Action CheckBurnRatePerDC
"""
import traceback
import json
from threading import Thread
from fawkes.connectors.alertrouter.alert_router import AlertRouterService, AlertRouterEvent
from fawkes.aiops.remediation_gus_utils import IccGUSRecordResponse
from fawkes.action import FawkesAction
from fawkes.connectors.argus.argus_query_service import FalconArgusConnector
from fawkes.connectors.vault.vault_service import VaultService
from fawkes.utils.time_utils import TimeUtils

from fawkes.constants import (
    FAWKES_ENV,
    FP_VAULT_BASE_PATH,
    FALCON_PLATFORM_COMPLETE_SECRETS_PATH,
    FALCON_ENV,
    FAWKES_AUTH_ENDPOINT,
    FAWKES_ST2_API_ENDPOINT,
    KVScope,
    FAWKES_UI_URL,
)

from st2client.client import Client
from st2client.models import Execution
from lib.assign_product_tag import AssignProductTag
from lib.conn_pool_burn_rate_dc import ConnPoolBurnRatePerDC
from lib.constants import (
    ARGUS_DASHBOARD_LINK_MILLIS,
    GUS_CREATE_OPERATION,
    GUS_UPDATE_OPERATION,
    RED_BUTTON_ENABLED_ALERT_ROUTER_MSG,
    CONN_POOL_BIG_RED_BUTTON_ON_STATUS_TTL_HOURS,
    FIRST_PARTY_SRE_CHANNEL,
    GIA_DATACENTERS,
    GOV_CLOUD_SRE_CHANNEL,
    FAWKES_APP_BOT_TOKEN_KEY,
    SLACK_CHANNEL_NAME_TO_CHANNEL_ID,
    CONN_POOL_BIG_RED_BUTTON_STATUS_KEY_NAME,
    CONN_POOL_BIG_RED_BUTTON_ON_STATUS,
    CONNPOOL_PODS_KEY_USING_BURN_RATE,
    CONNECTION_POOL_SLO_BURN_RATE_NODE_SCOPED_1HR_QUERY,
    CONNECTION_POOL_SLO_BURN_RATE_NODE_SCOPED_5MIN_QUERY,
    CONNECTION_POOL_SLO_BURN_RATE_POD_SCOPED_1HR_QUERY,
    CONNECTION_POOL_SLO_BURN_RATE_POD_SCOPED_5MIN_QUERY,
)

from lib.feed_operations import FeedOperations
from lib.notify_slack import NotifySlack
from lib.triage_and_remediation import TriageAndRemediate
from lib.utils import get_gus_client, get_prod_datacenters
from shared.common.utils import is_prod_env
from fawkes.core.platform_service import PlatformConnector

from runbooks.iscale.iscale_connpool_falcon.actions.lib.constants import (
    CONN_POOL_BIG_RED_BUTTON_NUM_OF_PODS_THRESHOLD_KEY_NAME,
)

if FAWKES_ENV == FALCON_ENV:
    _SLACK_CREDS_VAULT_PATH = FALCON_PLATFORM_COMPLETE_SECRETS_PATH
else:
    _SLACK_CREDS_VAULT_PATH = FP_VAULT_BASE_PATH.format(env=FAWKES_ENV.lower()) + "slack"

CONN_POOL_ALERT_ROUTER_LMT_KEY = "{dc}_alert_router_conn_pool_lmt"
CONN_POOL_ALERT_ROUTER_ALERT_ID = "Fawkes_Connection_pool_{pod}_{datacenter}"
ALERT_ROUTER_CLEAR_THRESHOLD_MILLIS = 900000  # 15 mins
CONN_POOL_ALERT_ROUTER_LMT_KEY_TTL = 24 * 60 * 60  # 24 hours


class CheckBurnRatePerDC(FawkesAction):
    """
    Action class to check for Connection Pool issues per Data Centre
    """

    ICA_ACTION_NAME = "aiops_fawkes_ica.incident_causation_action"

    def __init__(self, config=None, action_service=None):
        super(CheckBurnRatePerDC, self).__init__(config=config, action_service=action_service)
        self._vault_client = VaultService()
        # setup for client for action executions
        self.client = Client(auth_url=FAWKES_AUTH_ENDPOINT, api_url=FAWKES_ST2_API_ENDPOINT)
        self.metadata = None
        self.investigation_id = None
        self._platform_service = PlatformConnector()

        # api to init the Burn rate Key: Key, Value : []
        self.init_burn_rate()
        self.pods_with_burnrate_enabled = []

    def init_burn_rate(self):
        """
        API to init burn rate
        """

        # Check if the KV storage contains something ?, If Key is not present we
        # will initialize it, if its  present we will skip and just use what data is present in the KV storage

        burn_rate_pods = self.get_value(CONNPOOL_PODS_KEY_USING_BURN_RATE, KVScope.PACK)
        self.logger.info("Pod Details initialized for Burn rate : %s", burn_rate_pods)

        if burn_rate_pods:
            self.logger.info("Burn rate pods have been initialized")

        else:
            self.logger.info("No KV initialized for Burn rate, set the value now")
            pod_details = dict()
            pod_details["pods"] = []
            self.set_value(CONNPOOL_PODS_KEY_USING_BURN_RATE, json.dumps(pod_details), KVScope.PACK)

    def do_run(
        self,
        dc,
        connection_pool_burn_rate_threshold_5min,
        connection_pool_burn_rate_threshold_1hr,
        query_start_timestamp_millis,
        query_end_timestamp_millis,
        create_investigation,
        create_case,
        create_slack_notification,
    ):
        """
        Action to fetch Connection Pool Burn rate per DC
        """
        # Check if the conn. pool big red button has been pressed. If ON, we skip the run.
        # Note: Below get_value would return None in case of failure. In this case we are continuing the workflow.

        conn_pool_big_red_button_status = self.get_value(CONN_POOL_BIG_RED_BUTTON_STATUS_KEY_NAME)
        if conn_pool_big_red_button_status == CONN_POOL_BIG_RED_BUTTON_ON_STATUS:
            self.logger.info(
                "conn. pool's big red button has been set to True. failing the conn. pool action for DC: %s", dc
            )

        self.pods_with_burnrate_enabled = json.loads(self.get_value(CONNPOOL_PODS_KEY_USING_BURN_RATE, KVScope.PACK))[
            "pods"
        ]

        argus_service = FalconArgusConnector()

        # Convert into KV pair structure with key as : production_cells_burnrate
        # Value is an array of cells where the Burn rate feature is enabled
        # }}
        # initially the value should be empty

        self.pods_with_burnrate_enabled = json.loads(self.get_value(CONNPOOL_PODS_KEY_USING_BURN_RATE, KVScope.PACK))[
            "pods"
        ]

        datacenters = get_prod_datacenters(self, dc)
        threads = []
        for datacenter in datacenters:
            thread = Thread(
                target=self.run_per_dc,
                args=[
                    argus_service,
                    datacenter,
                    connection_pool_burn_rate_threshold_5min,
                    connection_pool_burn_rate_threshold_1hr,
                    query_start_timestamp_millis,
                    query_end_timestamp_millis,
                    create_investigation,
                    create_case,
                    create_slack_notification,
                ],
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    def run_per_dc(
        self,
        argus_service,
        dc,
        connection_pool_burn_rate_threshold_5min,
        connection_pool_burn_rate_threshold_1hr,
        query_start_timestamp_millis,
        query_end_timestamp_millis,
        create_investigation,
        create_case,
        create_slack_notification,
    ):
        """
        Runs conn pool inspection for the given DC
        """

        # We need to run Burn rate query as well as the Waits query,
        # Only during incident creation we separate out on which one
        # should create the incident and which one should not
        # Both the Workflows should run for all cases.
        # Incident creation is handled based on KV pair.
        # If cell is in Burn rate KV pair then incident creation should be based on thresholds crossed for Burn rate
        # if not then incident creation is based on the Conn pool waits query

        # Burn rate interval for 5 min query :
        #  If the Start/End time stamp is not specified we need to use Current time for the queries
        if not query_end_timestamp_millis:
            current_time_millis = TimeUtils.get_current_time_in_millis()
            query_start_timestamp_millis = int(current_time_millis - 10 * 60 * 1000)
            query_end_timestamp_millis = int(current_time_millis - 5 * 60 * 1000)
        else:
            query_start_timestamp_millis = int(query_end_timestamp_millis - 5 * 60 * 1000)

        burn_rate_interval_5min = str(query_start_timestamp_millis) + ":" + str(query_end_timestamp_millis)

        # self.logger.info("Executing burn_rate_interval_5min:%s ", burn_rate_interval_5min)
        # POD Scoped burn rate query 5 min

        # Query argus to run the Burn rate per DC
        # run the new query for finding if the error thresholds are crossed
        argus_query_5min = CONNECTION_POOL_SLO_BURN_RATE_POD_SCOPED_5MIN_QUERY.format(
            interval=burn_rate_interval_5min, datacenter=dc.upper()
        )
        # self.logger.info(
        #    "Executing 5 min POD SCOPED for DC : %s, query: %s", dc, argus_query_5min,
        # )
        query_result_5min_pod_scoped = argus_service.query_argus(argus_query_5min)

        # NOde Scoped burn rate query 5 min
        argus_query_5min_node_scoped = CONNECTION_POOL_SLO_BURN_RATE_NODE_SCOPED_5MIN_QUERY.format(
            interval=burn_rate_interval_5min, datacenter=dc.upper()
        )
        # self.logger.info(
        #    "Executing 5 min NODE SCOPED for Data Center : %s, query: %s", dc, argus_query_5min_node_scoped,
        # )
        query_result_5min_node_scoped = argus_service.query_argus(argus_query_5min_node_scoped)

        # Burn rate interval for  1hr query :
        if not query_end_timestamp_millis:
            current_time_millis = TimeUtils.get_current_time_in_millis()
            query_start_timestamp_millis = int(current_time_millis - 65 * 60 * 1000)
            query_end_timestamp_millis = int(current_time_millis - 5 * 60 * 1000)
        else:
            query_start_timestamp_millis = int(query_end_timestamp_millis - 60 * 60 * 1000)

        burn_rate_interval_1hr = str(query_start_timestamp_millis) + ":" + str(query_end_timestamp_millis)

        # Pod Scoped
        # Query argus to run the Burn rate per falcon instance
        # run the new query for finding if the error thresholds are crossed
        argus_query_1hr = CONNECTION_POOL_SLO_BURN_RATE_POD_SCOPED_1HR_QUERY.format(
            interval=burn_rate_interval_1hr, datacenter=dc.upper()
        )
        # self.logger.info("Executing 1hr POD SCOPED for Data center %s, query: %s", dc, argus_query_1hr)
        query_result_1hr_pod_scoped = argus_service.query_argus(argus_query_1hr)

        # node scoped
        argus_query_1hr_node_scoped = CONNECTION_POOL_SLO_BURN_RATE_NODE_SCOPED_1HR_QUERY.format(
            interval=burn_rate_interval_1hr, datacenter=dc.upper()
        )
        # self.logger.info(
        #   "Executing 1hr NODE SCOPED for Data Center : %s, query: %s", dc, argus_query_1hr_node_scoped,
        # )
        query_result_1hr_node_scoped = argus_service.query_argus(argus_query_1hr_node_scoped)

        incidents = []
        if (query_result_5min_node_scoped or query_result_1hr_node_scoped) or (
            query_result_5min_pod_scoped or query_result_1hr_pod_scoped
        ):
            self.logger.info(
                "Conn Pool events present for Data center:%s, checking if it qualifies as an incident", dc,
            )
            # process conn pool to get affected cells
            incident_keys_burn_rate_based = ConnPoolBurnRatePerDC(self).process_conn_pool_burn_rate_calculation(
                (query_result_5min_pod_scoped, query_result_1hr_pod_scoped),
                (query_result_5min_node_scoped, query_result_1hr_node_scoped),
                (connection_pool_burn_rate_threshold_5min, connection_pool_burn_rate_threshold_1hr),
                dc,
                query_start_timestamp_millis,
                query_end_timestamp_millis,
            )

            # Combine incident keys generated by Conn pool wait and Burn rate and
            # then publish the one which will not be used for
            # incident generation to slack?

            # Assign product tag
            for incident_key in incident_keys_burn_rate_based:
                self.logger.info("Incident key from Burn rate:%s", incident_key)

                status, incident_data = AssignProductTag(self).exec_conn_pool_scenarios(incident_key)
                incident_data["scenario_identified"] = status

                self.logger.info(incident_data)

                if status and incident_data.get("fawkes_triage"):
                    # Check if the total number of cases created by fawkes are more than the pods_threshold_value set.
                    # If yes, press the conn. pool's big red button.
                    cases_threshold_value = self.get_value(CONN_POOL_BIG_RED_BUTTON_NUM_OF_PODS_THRESHOLD_KEY_NAME)

                    # Set the value to 5 if None, so that we are covered in case of above kv `get_value` call fails.
                    if cases_threshold_value is None:
                        cases_threshold_value = 5
                    else:
                        cases_threshold_value = int(cases_threshold_value)

                    # Get number of cases created by fawkes in last 10 minutes.
                    self.logger.info(
                        "[%s]big red button threshold number of cases are set to: %s", dc, cases_threshold_value,
                    )
                    num_of_cases_created_by_fawkes = self._get_num_of_cases_created_by_fawkes()

                    # Check if the total cases created by fawkes in last 10 minutes are greater than the threshold value
                    # If Yes, Press the big red button, send an alert and skip the creation of case/investigation etc.
                    if num_of_cases_created_by_fawkes and num_of_cases_created_by_fawkes >= cases_threshold_value:
                        self._press_conn_pool_big_red_button_and_alert(num_of_cases_created_by_fawkes)
                        return False, incidents

                    # Note: The below order is important as we populate the incident data at every step.

                    pod = incident_data.get("pod")
                    if pod in self.pods_with_burnrate_enabled:
                        # Burn rate query will be used for investigation creation
                        # Create Gus Investigation and Assign to correct product team
                        self._create_gus_investigation(create_investigation, incident_data)
                        self._trigger_ica(
                            incident_data.get("pod"),
                            incident_data.get("icc_incident", {}).get("slack_channel_id"),
                            incident_data.get("gus_investigation"),
                        )

                        # create SRE case
                        self._create_gus_case(create_case, incident_data)

                        # Notify SRE on slack
                        self._notify_on_slack_channel(create_slack_notification, incident_data)

                        # Raise alert via alert router to SRE
                        self._raise_pd_alert(incident_data)

                        # Store the incident details in KV store
                        self.set_value(incident_key, json.dumps(incident_data))

                        # Invoke the Conn Pool AD workflow
                        self.executeADWorkflow(incident_data, create_investigation, create_slack_notification)

                        # publish to Alert router even when burn rate is enabled
                        self._raise_conn_pool_alert(incident_data)

                        # append the incident data to return for the workflow
                        incidents.append({incident_key: incident_data})
                    else:
                        self.logger.info("[%s]Pod is in Conn Pool Waits workflow, not creating incident here", pod)

                        # publish to Alert router do nothing
                        self._raise_conn_pool_alert(incident_data)

            return True, incidents

        # return empty list for no Connection Pool issues
        self.logger.info("No Connection Pool events found for  DC: %s", dc)
        return True, incidents

    def generateMetaData(self, incident_data, create_investigation):
        """
        Generate meta data with dc, pod, superpod, investigation_id info
        """
        dc = incident_data.get("dc")
        pod = incident_data.get("pod")
        superpod = incident_data.get("superpod")

        self.metadata = {
            "pod": f"{pod}",
            "superpod": superpod.lower(),
            "datacenter": dc.lower(),
        }

        self.investigation_id = None
        if create_investigation:
            gus_investigation = incident_data.get("gus_investigation")
            self.logger.info("GUS Inv : %s", gus_investigation)

            self.investigation_id = gus_investigation.get("record_id")
            self.logger.info(" Inv ID : %s", self.investigation_id)

    def executeADWorkflow(self, incident_data, create_slack_notification):
        """
        Async execution of Conn Pool AD workflow
        """
        self.client.executions.create(
            Execution(
                action="iscale_connpool_ad.check_conn_pool_ad_per_pod",
                parameters={
                    "query_start_timestamp_millis": incident_data.get("start_time_millis"),
                    "query_end_timestamp_millis": incident_data.get("end_time_millis"),
                    "create_slack_notification": create_slack_notification,
                    "env_type": "1P",
                    "metadata": self.metadata,
                    "investigation_id": self.investigation_id,
                },
            )
        )

    def executeDeadlockDetectionWorkFlow(self, incident_data, create_slack_notification):
        """
        Async execution of Deadlock Detection workflow
        """
        self.client.executions.create(
            Execution(
                action="iscale_connpool_deadlock_detection.check_conn_pool_deadlock_per_pod",
                parameters={
                    "query_start_timestamp_millis": incident_data.get("start_time_millis"),
                    "query_end_timestamp_millis": incident_data.get("end_time_millis"),
                    "create_slack_notification": create_slack_notification,
                    "env_type": "1P",
                    "metadata": self.metadata,
                    "investigation_id": self.investigation_id,
                },
            )
        )

    def _trigger_ica(self, pod_or_cell, slack_channel, gus_investigation):
        """
        Triggers ICA action
        """
        try:
            params = {
                "pod_or_cell": pod_or_cell,
                "slack_channel": slack_channel,
                "trigger_all_swimlanes": "True",
            }
            self.logger.info(f"Triggering ICA action with params {params}")

            st2_execution_id = self._platform_service.trigger_st2_action(self.ICA_ACTION_NAME, params)

            ica_execution_url = FAWKES_UI_URL
            ica_execution_url += "/" + st2_execution_id
            self.logger.info(ica_execution_url)

            investigation_id = gus_investigation.get("record_id")
            if investigation_id is not None:
                feed_operations = FeedOperations(self)
                feed_operations.send_chatter_post(ica_execution_url, investigation_id)

        except Exception as exc:
            self.logger.exception(f"Failed to trigger ICA for {pod_or_cell}, error: {exc}")

    def _get_alert_router_key(self):
        """
        Gets the alert router api key from vault
        """
        if FAWKES_ENV == FALCON_ENV:
            vault_path = FALCON_PLATFORM_COMPLETE_SECRETS_PATH
        else:
            vault_path = FP_VAULT_BASE_PATH.format(env=FAWKES_ENV.lower()) + "alertrouter"

        return self._vault_client.fetch_secret(path=vault_path, secret_name="api_key")

    def _raise_pd_alert(self, incident_data):
        """
        Method to raise PD via alert router to SRE
        """
        try:
            if is_prod_env():
                self.logger.info("Sending pd via alert router")
                # raise alert router only when the case is created
                if (
                    incident_data.get("gus_case")
                    and incident_data.get("gus_case").get("operation") == GUS_CREATE_OPERATION
                ):
                    api_key = self._get_alert_router_key()
                    alert_router = AlertRouterService(api_key, self.runbook_context)

                    name = "Fawkes detected Connection Pool Burn rate threshold exceeded {scenario} for Pod: {pod}, DC: {datacenter}".format(
                        pod=incident_data.get("pod"),
                        datacenter=incident_data.get("dc"),
                        scenario=incident_data.get("scenario"),
                    )

                    event = AlertRouterEvent(
                        service="SRE-CRM-1P",
                        severity=2,
                        name=name,
                        description=name
                        + " StartTime: {start_time} , EndTime: {end_time}".format(
                            start_time=TimeUtils.get_date_time_string(incident_data.get("start_time_millis")),
                            end_time=TimeUtils.get_date_time_string(incident_data.get("end_time_millis")),
                        ),
                        sourceAlertId=CONN_POOL_ALERT_ROUTER_ALERT_ID.format(
                            pod=incident_data.get("pod"), datacenter=incident_data.get("dc"),
                        ),
                        source="Fawkes",
                        status="ACTIVE",
                        component="ConnectionPool",
                        knowledgeArticleId="ka2EE000000AR0XYAW",
                        custom={
                            "refocus": "True",
                            "AspectName": "CONNECTIONPOOL",
                            "Datacenter": incident_data.get("dc").upper(),
                            "SuperPod": incident_data.get("superpod").upper(),
                            "Pod": incident_data.get("pod"),
                            "Incident_Argus_Link": ARGUS_DASHBOARD_LINK_MILLIS.format(
                                start_time=str(incident_data.get("start_time_millis")),
                                end_time=str(incident_data.get("end_time_millis")),
                                datacenter=incident_data.get("dc").upper(),
                                superpod=incident_data.get("superpod").upper(),
                                pod=incident_data.get("pod"),
                            ),
                            "Current_View_of_Argus_Metrics": ARGUS_DASHBOARD_LINK_MILLIS.format(
                                start_time="-30m",
                                end_time="-0m",
                                datacenter=incident_data.get("dc").upper(),
                                superpod=incident_data.get("superpod").upper(),
                                pod=incident_data.get("pod"),
                            ),
                        },
                    )
                    alert_router.notify(event)
                    self.logger.info("Alert sent to alert router successfully")

                    # Store the timestamp of the incident in the KV store when it's detected for the first time.
                    conn_pool_alert_router_lmt_db_key = CONN_POOL_ALERT_ROUTER_LMT_KEY.format(
                        dc=incident_data.get("dc")
                    )
                    conn_pool_alert_router_lmt_values = self.get_value(conn_pool_alert_router_lmt_db_key)
                    if conn_pool_alert_router_lmt_values:
                        conn_pool_alert_router_lmt_values = json.loads(conn_pool_alert_router_lmt_values)
                        conn_pool_alert_router_lmt_values[incident_data["pod"]] = str(
                            TimeUtils.get_current_time_in_millis()
                        )
                        self.set_value(
                            key=conn_pool_alert_router_lmt_db_key,
                            value=json.dumps(conn_pool_alert_router_lmt_values),
                            ttl=CONN_POOL_ALERT_ROUTER_LMT_KEY_TTL,
                        )
                    else:
                        values = {incident_data["pod"]: str(TimeUtils.get_current_time_in_millis())}
                        self.set_value(
                            key=conn_pool_alert_router_lmt_db_key,
                            value=json.dumps(values),
                            ttl=CONN_POOL_ALERT_ROUTER_LMT_KEY_TTL,
                        )

                elif incident_data.get("gus_case"):
                    # Subsequent detections of the same incident will update the timestamp.
                    conn_pool_alert_router_lmt_db_key = CONN_POOL_ALERT_ROUTER_LMT_KEY.format(
                        dc=incident_data.get("dc")
                    )
                    conn_pool_alert_router_lmt_values = self.get_value(conn_pool_alert_router_lmt_db_key)
                    if conn_pool_alert_router_lmt_values:
                        conn_pool_alert_router_lmt_values = json.loads(conn_pool_alert_router_lmt_values)
                        if conn_pool_alert_router_lmt_values.get(incident_data["pod"]):
                            conn_pool_alert_router_lmt_values[incident_data["pod"]] = str(
                                TimeUtils.get_current_time_in_millis()
                            )
                            self.set_value(
                                key=conn_pool_alert_router_lmt_db_key,
                                value=json.dumps(conn_pool_alert_router_lmt_values),
                                ttl=CONN_POOL_ALERT_ROUTER_LMT_KEY_TTL,
                            )
        except Exception:
            self.logger.error("Exception while sending alert via alert router, %s", traceback.print_exc())

    def clear_alert_router_alert(self, dc):
        try:
            conn_pool_alert_router_lmt_db_key = CONN_POOL_ALERT_ROUTER_LMT_KEY.format(dc=dc)
            pods_with_active_pager = self.get_value(conn_pool_alert_router_lmt_db_key)
            if pods_with_active_pager:
                self.logger.info("unresolved pagers found for DC :%s in pods: %s", dc, pods_with_active_pager)
                pods_with_active_pager = json.loads(pods_with_active_pager)
                for pod in list(pods_with_active_pager):
                    lmt = int(pods_with_active_pager[pod])
                    curr_time = TimeUtils.get_current_time_in_millis()
                    if curr_time - lmt > ALERT_ROUTER_CLEAR_THRESHOLD_MILLIS:
                        api_key = self._get_alert_router_key()
                        alert_router = AlertRouterService(api_key, self.runbook_context)
                        alert_id = CONN_POOL_ALERT_ROUTER_ALERT_ID.format(pod=pod, datacenter=dc)
                        event = AlertRouterEvent(
                            service="SRE-CRM-1P",
                            severity=3,
                            sourceAlertId=alert_id,
                            source="Fawkes",
                            status="CLEAR",
                            component="ConnectionPool",
                            name="",
                            description="",
                        )
                        alert_router.notify(event)
                        self.logger.info("Cleared [%s] alert in alert router, pod=%s", alert_id, pod)
                        del pods_with_active_pager[pod]
                if len(pods_with_active_pager) == 0:
                    self.delete_value(conn_pool_alert_router_lmt_db_key)
                else:
                    self.set_value(conn_pool_alert_router_lmt_db_key, json.dumps(pods_with_active_pager))
        except Exception:
            self.logger.error("Exception while clearing alerts via alert router, %s", traceback.print_exc())

    def _create_gus_investigation(self, create_investigation, incident_data):
        """
        Method to deal with Investigation creation logic
        """
        dc = incident_data.get("dc")
        pod = incident_data.get("pod")
        try:
            if create_investigation:
                gus_inv_response = TriageAndRemediate(self, incident_data).create_or_update_gus_investigation()
                if gus_inv_response:
                    incident_data["gus_investigation"] = {
                        "record_id": gus_inv_response[0].record_id,
                        "operation": GUS_CREATE_OPERATION
                        if gus_inv_response[0].new_record or gus_inv_response[0].existing_but_created_by_others
                        else GUS_UPDATE_OPERATION,
                        "human_readable_record_id": gus_inv_response[0].human_readable_record_id,
                    }
                    self.logger.info("[%s][%s]Investigation Created successfully", dc, pod)
                return
            self.logger.info("[%s][%s]Investigation Creation Flag is disabled", dc, pod)

        except Exception:
            # Continue with the flow and log the error, since investigation creation is not the end goal
            self.logger.error("Exception while creating Investigation, %s", traceback.print_exc())

    def _create_gus_case(self, create_case, incident_data):
        """
        Method to deal with case creation logic
        """
        pod = incident_data.get("pod")
        dc = incident_data.get("dc")
        try:
            if create_case:
                gus_case_resp = TriageAndRemediate(self, incident_data).create_or_update_gus_sre_case()
                feed_operations = FeedOperations(self)
                if gus_case_resp:
                    incident_data["gus_case"] = {
                        "record_id": gus_case_resp[0].record_id,
                        "operation": GUS_CREATE_OPERATION
                        if gus_case_resp[0].new_record or gus_case_resp[0].existing_but_created_by_others
                        else GUS_UPDATE_OPERATION,
                        "human_readable_record_id": gus_case_resp[0].human_readable_record_id,
                    }

                    if isinstance(gus_case_resp[0], IccGUSRecordResponse):
                        incident_data["icc_incident"] = {
                            "incident_id": gus_case_resp[0].icc_incident_id,
                            "slack_channel_id": gus_case_resp[0].slack_channel_id,
                            "slack_channel_name": gus_case_resp[0].slack_channel_name,
                        }

                    # Create Chatter Post on Case with Investigation details
                    feed_operations.create_post_on_case(incident_data,)
                    self.logger.info("Case Created successfully and feed updated")
                return
            self.logger.info("skipping case creation as create_case is set to False %s datacenter: %s", pod, dc)
        except Exception:
            # Continue with the flow and log the error, since Case creation is not the end goal
            self.logger.error("[%s][%s]Exception while creating case, %s", dc, pod, traceback.print_exc())

    def _create_remediation_incident(self, create_remediation_incident, incident_data):
        """
        Method to create Remediation Incident
        """
        try:
            if create_remediation_incident:
                result, _creation_status = TriageAndRemediate(
                    self, incident_data
                ).create_or_update_remediation_incident()
                if result:
                    incident_data["remediation_guid"] = result.get("guid")

                    self.logger.info("Remediation Incident created successfully, guid = %s ", result.get("guid"))
                return
            self.logger.info("Remediation Incident Creation Flag is disabled")

        except Exception:
            # Continue with the flow and log the error, since Remediation Incident creation is not the end goal
            self.logger.error("Exception while creating Remediation Incident, %s", traceback.print_exc())

    def _get_num_of_cases_created_by_fawkes(self, past_minutes_diff=60):
        # pylint:disable=trailing-whitespace
        """
        Return the number of cases created by Fawkes in past `past_minutes_diff` minutes.
        :param past_minutes_diff: go back past_minutes_diff minutes and query for cases created after that timestamp.
        """
        # Get GUS compatible time string for the SOQL query.
        time_stamp = TimeUtils.get_current_time_in_millis() - (past_minutes_diff * 60 * 1000)
        gus_compatible_time_string = TimeUtils.get_gus_compatible_time_string(time_stamp)

        # SOQL query to get cases created by fawkes in past `past_minutes_diff` minutes.
        num_cases_query = (
            """
            SELECT Id FROM Case WHERE RecordTypeId = '012B000000009fCIAQ'
                                AND CreatedById = '005AH000000HtZbYAK'
                                AND Priority in ('Sev2', 'Sev1', 'Sev0') 
                                AND Subject	like '%%Connection Pool Timeouts due%%'
                                AND CreatedDate > %s.000Z"""
            % gus_compatible_time_string
        )

        # GUS client to run SOQL query.
        gus_client = get_gus_client(self.runbook_context)
        soql_response = gus_client.run_soql(num_cases_query)

        # 'totalSize' will give the number of cases created by fawkes in last `past_minutes_diff` minutes.
        if soql_response:
            total_records_returned = soql_response.get("totalSize", 0)
            self.logger.info("SOQL query: %s has returned %s cases", num_cases_query, total_records_returned)
            return total_records_returned
        return None

    def _press_conn_pool_big_red_button_and_alert(self, num_of_cases_created):
        """
        Method to set the big red button value to True and send an email.
        :param num_of_cases_created: number of cases created by Fawkes.
        :return: True if successful in pressing the big red button or else False.
        """
        # Set CONN_POOL_BIG_RED_BUTTON_STATUS_KEY_NAME flag to ON.
        self.set_value(
            CONN_POOL_BIG_RED_BUTTON_STATUS_KEY_NAME,
            CONN_POOL_BIG_RED_BUTTON_ON_STATUS,
            ttl=CONN_POOL_BIG_RED_BUTTON_ON_STATUS_TTL_HOURS * 60 * 60,
        )
        self.logger.info(
            "conn. pool's big red button key: %s has been set to: %s",
            CONN_POOL_BIG_RED_BUTTON_STATUS_KEY_NAME,
            CONN_POOL_BIG_RED_BUTTON_ON_STATUS,
        )

        # Send alert router event to Fawkes
        msg = (
            "[Test][Pls Ignore]" + RED_BUTTON_ENABLED_ALERT_ROUTER_MSG
            if not is_prod_env()
            else RED_BUTTON_ENABLED_ALERT_ROUTER_MSG
        )
        self._send_big_red_button_alert(
            msg.format(cases=num_of_cases_created, ttl=CONN_POOL_BIG_RED_BUTTON_ON_STATUS_TTL_HOURS)
        )

    def _send_big_red_button_alert(self, msg):
        """
        Sends alert router event to Fawkes team
        """
        if is_prod_env():
            alert_router = AlertRouterService(self._get_alert_router_key(), self.runbook_context)
            current_time = TimeUtils.get_current_time_string()
            event = AlertRouterEvent(
                service="fawkes",
                severity=3,
                name="Connection Pool Big red button enabled",
                description=msg,
                sourceAlertId=f"conn-pool-alert_{current_time}",
                source="Fawkes",
                component="connection-pool",
                status="ACTIVE",
            )
            alert_router.notify(event)
            self.logger.info("Sent big red button alert to alert router")

    def _notify_on_slack_channel(self, create_slack_notification, incident_data):
        # IF GIA pod, we have to alert on a different channel.
        if create_slack_notification:
            slack_bot_token = self._vault_client.fetch_secret(
                path=_SLACK_CREDS_VAULT_PATH, secret_name=FAWKES_APP_BOT_TOKEN_KEY,
            )
            if incident_data.get("dc").upper() in GIA_DATACENTERS:
                alert_channel_id = SLACK_CHANNEL_NAME_TO_CHANNEL_ID.get(GOV_CLOUD_SRE_CHANNEL, None)
            else:
                alert_channel_id = SLACK_CHANNEL_NAME_TO_CHANNEL_ID.get(FIRST_PARTY_SRE_CHANNEL, None)
            NotifySlack(slack_bot_token, alert_channel_id, self).notify_slack(incident_data)
        else:
            self.logger.info(
                "[%s]not alerting on slack channel as slack notifications are disabled", incident_data.get("dc")
            )

    def _raise_conn_pool_alert(self, incident_data):
        """
        Method to raise Conn pool alert via alert router to Conn pool team
        """
        try:
            self.logger.info("Sending conn pool alert via alert router")
            # raise alert router only when the case is created
            api_key = self._get_alert_router_key()
            alert_router = AlertRouterService(api_key, self.runbook_context)

            name = " Fawkes detected Connection Pool Burn rate threshold exceeded for Pod: {pod}, DC: {datacenter}, Scenario: {scenario}".format(
                pod=incident_data.get("pod"),
                datacenter=incident_data.get("dc"),
                scenario=incident_data.get("scenario"),
            )

            event = AlertRouterEvent(
                service="connection-pool",
                severity=4,
                name=name,
                description=name
                + " StartTime: {start_time} , EndTime: {end_time}".format(
                    start_time=TimeUtils.get_date_time_string(incident_data.get("start_time_millis")),
                    end_time=TimeUtils.get_date_time_string(incident_data.get("end_time_millis")),
                ),
                sourceAlertId=CONN_POOL_ALERT_ROUTER_ALERT_ID.format(
                    pod=incident_data.get("pod"), datacenter=incident_data.get("dc"),
                ),
                source="Fawkes",
                status="ACTIVE",
                component="ConnectionPool",
                knowledgeArticleId="ka2EE000000AR0XYAW",
                custom={
                    "refocus": "True",
                    "AspectName": "CONNECTIONPOOL",
                    "Datacenter": incident_data.get("dc").upper(),
                    "SuperPod": incident_data.get("superpod").upper(),
                    "Pod": incident_data.get("pod"),
                    "Incident_Argus_Link": ARGUS_DASHBOARD_LINK_MILLIS.format(
                        start_time=str(incident_data.get("start_time_millis")),
                        end_time=str(incident_data.get("end_time_millis")),
                        datacenter=incident_data.get("dc").upper(),
                        superpod=incident_data.get("superpod").upper(),
                        pod=incident_data.get("pod"),
                    ),
                    "Current_View_of_Argus_Metrics": ARGUS_DASHBOARD_LINK_MILLIS.format(
                        start_time="-30m",
                        end_time="-0m",
                        datacenter=incident_data.get("dc").upper(),
                        superpod=incident_data.get("superpod").upper(),
                        pod=incident_data.get("pod"),
                    ),
                },
            )
            alert_router.notify(event)
            self.logger.info("Alert sent to alert router successfully")

        except Exception:
            self.logger.error("Exception while sending alert via alert router, %s", traceback.print_exc())
