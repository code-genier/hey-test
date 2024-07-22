from runbooks.casp.casp_connpool.actions.get_prod_data_centers import get_prod_pod

# pylint: disable=broad-except,R0201,W0613,E1111,E1128,R0902
"""
Action for app rolling restart actiond
"""
import datetime
import json
import os
import traceback

from fawkes.action import FawkesAction
from fawkes.api.remediation import Remediation
from fawkes.connectors.gus.gus_change_management import GUSChangeManagement
from fawkes.connectors.gus.gus_objects import GUSCase, GUSChangeImplementationStep, GUSChangeCase
from fawkes.connectors.slack.message import Message
from fawkes.core.platform_service import PlatformConnector
from fawkes.utils.app_capacity_utils import app_server_ping_alive_percent
from fawkes.utils.env_utils import is_dev_env
from fawkes.utils.logging_utils import FawkesLogger
from fawkes.utils.time_utils import TimeUtils
from fawkes.constants import (
    SSL_CAFILE,
    SSL_CERTFILE,
    SSL_KEYFILE,
    AJNA_ENDPOINT,
)
from statslib.senders.argus_sender import ArgusSender
from lib.constants import (
    ISSUE_ROLLING_RESTART,
    CHANGE_IMPLEMENTATION_COMPLETED,
    RR_RECEIVED_MSG,
    GUS_FIELD_NAME_STATUS,
    GUS_FIELD_NAME_CATEGORY,
    GUS_FIELD_NAME_ROOTCAUSE,
    GUS_FIELD_NAME_IMMEDIATE_RESOLUTION,
    DEV_USERS,
    CASP_TEAM_ID,
    CASE_SEVERITY,
    RR_CASE_SUBJECT,
    ROLLING_RESTART_STATE_TRANSITION_MSG,
    STATSLIB_SERVICE_NAME,
    STATSLIB_CONFIG_PATH,
    ROLLING_RESTART_EXECUTION_TIME,
)
from rr_utils import EventType, RollingRestartAllocation, RollingRestartAction, add_event, query_logical_hosts
from shared.common.utils import is_prod_env, parse_sfdc_hostname
from shared.remediation.argus import get_argus_client
from shared.remediation.config import get_issue_config, IssueType
from shared.remediation.constants import (
    FAWKES_EXECUTION_LOGS_URL,
    REMEDIATION_SERVICE_ACCOUNT,
    PING_ALIVE_PERCENT,
    _INFRASTRUCTURE_TYPE_CHANGE_CASE,
    _FIREFLY_FCP_PIPELINE,
    _SOURCE_CONTROL_TOOL,
    _TESTING_METHOD_CHANGE_CASE,
    OPERATIONAL_STATUS,
)
from shared.remediation.enums import State
from shared.remediation.gus import RemediationGusClient
from shared.remediation.maiev_remediation_service import MaievRemediationMetadata, MaievRemediationService
from shared.remediation.utils import get_slack_bot_token
from shared.remediation.validations.capacity_validation import (
    CapacityValidation,
    CapacityRetrievalFailed,
    LowPodCapacity,
)

ISSUE_TYPE_ROLLING_RESTART = "app-rolling-restart"

RR_KV_LOCK = "rolling_restart_processor"
RR_GUID = "guid"
RR_MESSAGE_TS_KEY = "RR_{guid}_TS"
RR_POD_INITIAL_CAPACITY = "RR_{guid}_pod_initial_capacity"
RR_ACTIVE_HOST_COUNT = "RR_{guid}_active_host_count"

KV_TTL_SECONDS = 24 * 60 * 60

FIELD_ADDITIONAL_INFO = "additional_info"
FIELD_STATE = "state"

EXPIRE_CUTOFF_HOURS = 5
LOOK_BACK_HOURS = 12
CAPACITY_THRESHOLD = 50

# rolling restart states
STATE_NEW = "NEW"
STATE_IN_PROGRESS = "IN_PROGRESS"
STATE_POST_EXECUTION = "POST_EXECUTION"
STATE_STOPPED = "STOPPED"
STATE_CANCELLED = "CANCELLED"
STATE_FAILED = "FAILED"
STATE_COMPLETED = "COMPLETED"
STATE_TIMED_OUT = "TIMED_OUT"
FINAL_STATES = [STATE_STOPPED, STATE_CANCELLED, STATE_FAILED, STATE_COMPLETED, STATE_TIMED_OUT]
REMEDIATION_FINAL_STATES = [State.EXPIRED.value, State.FAILED.value, State.SUCCESSFUL.value, State.NOT_EXECUTED.value]

# host states
HOST_STATE_PENDING = "PENDING"
HOST_STATE_VALIDATION_FAILED = "HOST_VALIDATION_FAILED"
HOST_STATE_REMEDIATION_CREATED = "REMEDIATION ACTION CREATED"
HOST_STATE_CANCELLED = "CANCELLED"
HOST_STATE_FAILED = "FAILED"
HOST_FINAL_STATES = [HOST_STATE_VALIDATION_FAILED, HOST_STATE_CANCELLED, HOST_STATE_FAILED]

# update this to 'rolling-restart' after final testing
ISSUE_ROLLING_RESTART = "app-rolling-restart"

logger = FawkesLogger.get_logger(__name__)

from runbooks.casp.casp_ppx.actions import casp_base_detector


class AppRollingRestartAction(FawkesAction):
    """
    Class for RollingRestart actions on core app
    """

    def __init__(self, config=None, action_service=None):
        super(AppRollingRestartAction, self).__init__(config=config, action_service=action_service)
        self.logger = logger
        if self.get_value(RR_KV_LOCK):
            self.logger.error("Another instance of rolling restart processor is running.. Exiting.")
            raise Exception("Another instance of rolling restart processor is running")
        self.set_value(RR_KV_LOCK, TimeUtils.get_current_time_in_millis(), ttl=150)
        self.remediation_api_client = Remediation()

    # pylint: disable=R0912
    def do_run(self, **kwargs):
        """
        RollingRestartAction implementation
        """
        # get all active executions
        active_rolling_restarts = self.get_active_rolling_restarts()
        if active_rolling_restarts:
            logger.info(f"Found {len(active_rolling_restarts)} active rolling restart executions")
            for execution in active_rolling_restarts:
                try:
                    self.logger.info(f"Tracking rolling restart action with guid: {execution['guid']}")
                    processor = self.RollingRestartProcessor(execution, self.config, self.action_service)
                    processor.run()
                except Exception as exc:
                    self.logger.error(
                        f"Rolling restart processor failed for execution {execution['guid']}, error: {str(exc)}",
                        exc_info=True,
                    )
        self.delete_value(RR_KV_LOCK)

    def get_active_rolling_restarts(self):
        """
        Gets all active (NEW / IN_PROGRESS) rolling restarts from db
        """
        look_back_window = TimeUtils.get_current_time_in_millis() - (LOOK_BACK_HOURS * 60 * 60 * 1000)
        return self.remediation_api_client.get_filtered_rolling_restart_actions(
            json.dumps(
                {
                    "state": {"$nin": FINAL_STATES},
                    "created_by": {"$nin": DEV_USERS},
                    "additional_info.version": "v2",
                    "creation_ts_millis": {"$gte": look_back_window},
                },
            )
        )

    class RollingRestartProcessor(FawkesAction):
        def do_run(self, **kwargs):
            """
            Dummy method to use FawkesAction
            """
            raise NotImplementedError

        def __init__(self, rolling_restart, config=None, action_service=None):
            super().__init__(config=config, action_service=action_service)
            self.logger = logger
            self.is_first_batch = False
            self.issue: IssueType = get_issue_config(ISSUE_ROLLING_RESTART)
            # TODO: Move all connectors outside to avoid re-init
            self.platform_service = PlatformConnector()
            self.remediation_api_client = Remediation()
            self.gus_client = RemediationGusClient.get_instance()
            self.gus_cm_client = GUSChangeManagement(gus_client=self.gus_client)
            self.argus_client = get_argus_client()
            self.slack_bot_token = get_slack_bot_token()
            self.slack = Message(runbook_context=self.runbook_context)

            datacenter = parse_sfdc_hostname(rolling_restart["hosts"][0])["datacenter"]
            self.active_hosts_count, self.pod_initial_capacity = self.get_initial_capacity_state(
                rolling_restart["guid"], rolling_restart["pod"], datacenter
            )

            self.rolling_restart = self.parse_rr_dict(rolling_restart)
            self.slack_alert_ts = self.rolling_restart.slack_alert_ts
            self.capacity_validation = CapacityValidation(
                hostname=self.rolling_restart.hosts[0], issue=get_issue_config(ISSUE_TYPE_ROLLING_RESTART)
            )

            # variables to support legacy validation classes
            self.rolling_restart_guid = self.rolling_restart.guid
            self.hosts_to_be_restarted = self.rolling_restart.hosts
            self.pod = self.rolling_restart.pod

            # set capacity threshold
            if self.rolling_restart.run_capacity_check:
                self.capacity_cutoff_threshold = CAPACITY_THRESHOLD
            else:
                # uses 80 as max cutoff threshold when capacity is above 80
                self.capacity_cutoff_threshold = (
                    self.pod_initial_capacity if self.pod_initial_capacity < CAPACITY_THRESHOLD else CAPACITY_THRESHOLD
                )

            self.allocation_status: RollingRestartAllocation = self.get_current_allocation()

            self.capacity_check_done = False
            self.execution_logs = FAWKES_EXECUTION_LOGS_URL.format(
                execution_id=os.getenv("ST2_ACTION_EXECUTION_ID", "")
            )
            self.superpod = None
            self.datacenter = parse_sfdc_hostname(self.rolling_restart.hosts[0])["datacenter"]
            logical_hosts = query_logical_hosts(self.rolling_restart.hosts, self.gus_client)
            if logical_hosts:
                self.superpod = logical_hosts[0]["Super_Pod__c"].split("-")[1]
            self.argus_sender = ArgusSender(
                end_point=AJNA_ENDPOINT,
                config_file_path=STATSLIB_CONFIG_PATH,
                certs=(SSL_CERTFILE, SSL_KEYFILE),
                verify=SSL_CAFILE,
            )
            self.argus_sender.config["service_name"] = STATSLIB_SERVICE_NAME

        def run(self):
            """
            Run processors for respective states
            """
            if self.is_cancelled():
                return

            if self.is_expired():
                return

            if self.rolling_restart.state == STATE_NEW:
                self.rolling_restart_execution_preprocessor()

            if self.rolling_restart.state == STATE_IN_PROGRESS:
                self.rolling_restart_execution_processor()

            if self.rolling_restart.state in FINAL_STATES:
                self.rolling_restart_execution_postprocessor()

        def rolling_restart_execution_preprocessor(self):
            """
            Handles rolling restarts pre execution steps
            """
            self.is_first_batch = True
            self.add_event("********** Running rolling restart pre-processor **********")

            if self.rolling_restart.group_percentage > 50:
                self.add_event("Invalid batch size, Maximum supported value is 50%")
                self.update_rolling_restart_status(STATE_FAILED)
                return

            self.add_event(
                f"Number of hosts to be restarted : {len(self.rolling_restart.hosts)}, "
                f"Total active hosts in pod : {self.active_hosts_count} "
                f"Group percentage: {self.rolling_restart.group_percentage}, "
                f"Batch size : {self.rolling_restart.batch_size}, "
                f"Action : {self.rolling_restart.action}"
            )

            message_ts = self.send_slack_message(
                RR_RECEIVED_MSG.format(
                    hosts_count=len(self.rolling_restart.hosts),
                    pod=self.rolling_restart.pod,
                    group_percent=self.rolling_restart.group_percentage,
                    batch_size=self.rolling_restart.batch_size,
                    initiator=self.get_initiator(self.rolling_restart.created_by),
                    logs_url=self.execution_logs,
                )
            )
            self.set_value(RR_MESSAGE_TS_KEY.format(guid=self.rolling_restart.guid), message_ts, ttl=KV_TTL_SECONDS)

            # run capacity validations for pod
            if self.rolling_restart.run_capacity_check:
                self.add_event(f"Running capacity validations for pod {self.rolling_restart.pod}")
                try:
                    self.run_capacity_validation()
                    self.add_event("Capacity validation PASSED")
                except Exception as exc:
                    self.add_event(f"Pod capacity validation failed, Error : {exc}")
                    self.update_rolling_restart_status(STATE_FAILED)
                    return
            else:
                self.add_event(
                    "Capacity validation is disabled for this execution. Using initial capacity of pod as "
                    "cutoff threshold",
                    EventType.WARNING,
                )
            self.add_event(f"Capacity cutoff threshold = {self.capacity_cutoff_threshold}", EventType.WARNING)

            case = None
            if not is_dev_env() and self.rolling_restart.create_change_case:
                try:
                    self.add_event("Creating change case record")
                    case = self.create_change_case()
                    self.add_event(f"Change case record : https://gus.my.salesforce.com/{case['id']}")
                    self.add_event("Starting implementation step")
                    self.gus_start_implementation(case)
                except Exception as exc:
                    self.add_event(f"Change case creation failed, error : {exc}", EventType.ERROR)
                    self.logger.info(f"Case creation failed, error : {exc}, traceback : {traceback.format_exc()}")
                    self.update_rolling_restart_status(STATE_FAILED, gus_case=case)
                    raise Exception(exc)
            else:
                try:
                    self.add_event("Creating incident case record")
                    case = self.create_gus_case()
                    self.add_event(f"Incident case record : https://gus.my.salesforce.com/{case['id']}")
                except Exception as exc:
                    self.add_event(f"Incident case creation failed, error : {exc}", EventType.WARNING)
                    self.logger.info(f"Case creation failed, error : {exc}, traceback : {traceback.format_exc()}")
            self.update_rolling_restart_status(STATE_IN_PROGRESS, gus_case=case)

        def rolling_restart_execution_processor(self):
            """
            Handles ongoing rolling restarts execution steps
            """
            self.add_event("********** Running rolling restart processor **********")
            current_allocation = self.get_current_allocation()
            self.add_event(
                f"current status > skipped: {current_allocation.skipped} | pending : {current_allocation.pending} |"
                f" in_progress : {current_allocation.in_progress} | completed : {current_allocation.completed}"
            )
            self.add_event(f"Available slots in batch: {current_allocation.available_batch_size}")
            if current_allocation.available_batch_size and current_allocation.pending_hosts:
                next_batch = current_allocation.pending_hosts[: current_allocation.available_batch_size]

                try:
                    # capacity check already done for first batch in pre-processor. Not repeating if flag is set
                    if not self.is_first_batch:
                        self.run_capacity_validation()
                except LowPodCapacity:
                    # Stop rolling restart if capacity checks fail with all slots in batch are available
                    if self.rolling_restart.batch_size == current_allocation.available_batch_size:
                        self.add_event(
                            "Stopping rolling restart execution as capacity is below cutoff threshold", EventType.ERROR
                        )
                        self.update_rolling_restart_status(STATE_STOPPED)
                    else:
                        self.add_event(
                            f"Waiting for {current_allocation.in_progress} hosts to come up as capacity is below "
                            f"cutoff threshold",
                            EventType.WARNING,
                        )
                    return
                except Exception as exc:
                    self.add_event(
                        f"Failed to retrieve Capacity report, will retry during next processor run, Error: {exc}",
                        EventType.ERROR,
                    )
                    return

                self.trigger_restart_action(next_batch)

            # update allocation status
            current_allocation = self.get_current_allocation()
            if len(self.rolling_restart.hosts) == (current_allocation.completed + current_allocation.skipped):
                self.update_rolling_restart_status(STATE_COMPLETED)
                self.add_event(
                    f"Rolling restart completed. Summary :: "
                    f"Total Hosts : {current_allocation.skipped + current_allocation.completed} | "
                    f"Completed: {current_allocation.completed} | Skipped : {current_allocation.skipped}"
                )
            else:
                self.add_event(
                    f"current status > skipped: {current_allocation.skipped} | pending : {current_allocation.pending} |"
                    f" in_progress : {current_allocation.in_progress} | completed : {current_allocation.completed}"
                )
                self.add_event(f"Available slots in batch: {current_allocation.available_batch_size}")

        def rolling_restart_execution_postprocessor(self):
            """
            Handles rolling restarts post execution steps
            """
            self.add_event("********** Running rolling restart post-processor ********** ")
            # close case
            try:
                if self.rolling_restart.create_change_case:
                    if self.rolling_restart.gus_case and self.rolling_restart.gus_case.get("implementationSteps"):
                        self.gus_stop_implementation()
                        self.close_change_case()
                        self.add_event("Closed change case")
                else:
                    self.close_gus_case()
                    self.add_event("Closed incident case")
                self.publish_metrics()
            except Exception as exc:
                self.add_event(f"Failed to close case, Error: {exc}")

        def publish_metrics(self):
            """
            publish metric to argus for rolling restart
            """
            try:
                time_taken_millis = TimeUtils.get_current_time_in_millis() - self.rolling_restart.creation_ts_millis
                time_taken_minutes = time_taken_millis / (1000 * 60)
                self.logger.info(
                    "sending execution metric to argus for pod %s, time taken=%s min",
                    self.rolling_restart.pod,
                    time_taken_minutes,
                )
                self.argus_sender.send(
                    ROLLING_RESTART_EXECUTION_TIME,
                    value=time_taken_minutes,
                    tags={
                        "pod": self.rolling_restart.pod,
                        "dc": self.rolling_restart.datacenter,
                        "status": self.rolling_restart.state,
                    },
                )
                self.argus_sender.shutdown()
            except Exception as error:
                self.logger.error("Exception while sending argus metric, error:%s", error)

        def add_event(self, event_msg, event_type: EventType = EventType.INFO):
            """
            Adds event to rolling restart object
            @param event_msg: event text message
            @param event_type: type of event (INFO, ERROR, WARNING)
            """
            add_event(self.rolling_restart.guid, event_msg, logger, event_type)

        def send_slack_message(self, message):
            """
            send message to slack channel
            """
            if self.rolling_restart.notify_slack:
                try:
                    message_ts = self.slack.send_thread_message(
                        self.slack_bot_token, self.rolling_restart.slack_channel_id, message, self.get_message_ts(),
                    )
                    return message_ts
                except Exception as error:
                    self.logger.error("slack message sending failed with error:%s", error)

        def calculate_batch_size(self, group_percent):
            """
            Calculates the batch size of restarts based on the total hosts in pod and group percentage
            """
            return round(self.active_hosts_count * group_percent / 100) or 1

        # def reject_hosts_failed_validation(self, hosts):
        #     """
        #     Mark hosts failed validation as rejected
        #     """
        #     for host in hosts:
        #         self.remediation_api_client.update_rolling_restart_host_status(
        #             self.rolling_restart.guid, host, HOST_STATE_VALIDATION_FAILED
        #         )
        #     if hosts:
        #         self.send_slack_message(f"Rejects hosts failing validation {hosts}")
        #     self.sync_rolling_restart_object()

        def get_current_allocation(self):
            """
            Returns current batch allocation (how many host restarts are in progress)
            """
            # sync object with db before calculating capacity
            self.sync_rolling_restart_object()
            rolling_restart_status = self.rolling_restart.status
            remediation_actions = self.remediation_api_client.get_filtered_actions(
                json.dumps({"rolling_restart_guid": self.rolling_restart.guid})
            )

            pending = 0
            skipped = 0
            in_progress = 0
            completed = 0
            pending_hosts = []

            for host, status in rolling_restart_status.items():
                # parse host field to hostname (hostname key in status field contain underscore instead of dots)
                hostname = host.replace("_", ".")
                if status["state"] == HOST_STATE_PENDING:
                    pending += 1
                    pending_hosts.append(hostname)
                elif status["state"] == HOST_STATE_VALIDATION_FAILED:
                    skipped += 1
                elif status["state"] in HOST_FINAL_STATES:
                    completed += 1
                elif status["state"] == HOST_STATE_REMEDIATION_CREATED:
                    found = False
                    for action in remediation_actions:
                        if action["hostname"] == hostname:
                            found = True
                            remediation_state = action["state"]
                            if remediation_state in REMEDIATION_FINAL_STATES:
                                completed += 1
                            else:
                                in_progress += 1
                            continue
                    if not found:
                        self.add_event(f"Remediation object not found for host {host}", EventType.ERROR)
                else:
                    self.logger.error(
                        f"[{self.rolling_restart.guid}] Unhandled status '{status['state']}' found for {host}"
                    )
            available_batch_size = self.rolling_restart.batch_size - in_progress
            return RollingRestartAllocation(
                pending=pending,
                skipped=skipped,
                in_progress=in_progress,
                completed=completed,
                available_batch_size=available_batch_size,
                pending_hosts=pending_hosts,
            )

        def parse_rr_dict(self, rolling_restart):
            """
            Creates named tuple from rolling restart dict
            """
            return RollingRestartAction(
                guid=rolling_restart["guid"],
                pod=rolling_restart["pod"],
                datacenter=parse_sfdc_hostname(rolling_restart["hosts"][0])["datacenter"],
                state=rolling_restart["state"],
                hosts=rolling_restart["hosts"],
                created_by=rolling_restart["created_by"],
                creation_ts_millis=rolling_restart["creation_ts_millis"],
                last_updated_timestamp=rolling_restart["last_updated_timestamp"],
                group_percentage=rolling_restart["group_percentage"],
                batch_size=self.calculate_batch_size(rolling_restart["group_percentage"]),
                is_cancelled=rolling_restart[FIELD_ADDITIONAL_INFO].get("cancellation"),
                action=rolling_restart[FIELD_ADDITIONAL_INFO].get("action"),
                notify_slack=rolling_restart[FIELD_ADDITIONAL_INFO].get("notify_slack", True),
                slack_channel_id=rolling_restart[FIELD_ADDITIONAL_INFO].get(
                    "slack_channel_id", self.issue.slack_channel
                )
                if is_prod_env()
                else self.issue.slack_channel_dev,
                slack_alert_ts=rolling_restart[FIELD_ADDITIONAL_INFO].get("slack_alert_ts"),
                run_capacity_check=rolling_restart[FIELD_ADDITIONAL_INFO].get("run_capacity_check"),
                run_host_level_prechecks=rolling_restart[FIELD_ADDITIONAL_INFO].get("run_host_level_prechecks"),
                run_health_checks_after_each_group=rolling_restart[FIELD_ADDITIONAL_INFO].get(
                    "run_health_checks_after_each_group"
                ),
                select_all_hosts=rolling_restart[FIELD_ADDITIONAL_INFO].get("select_all_hosts"),
                disable_host_alerts=rolling_restart[FIELD_ADDITIONAL_INFO].get("disable_host_alerts"),
                status=rolling_restart[FIELD_ADDITIONAL_INFO].get("status"),
                create_change_case=rolling_restart[FIELD_ADDITIONAL_INFO].get("create_change_case"),
                gus_case=rolling_restart[FIELD_ADDITIONAL_INFO].get("gus_case"),
            )

        @staticmethod
        def get_initiator(created_by_user):
            return "fawkes-automation" if created_by_user == REMEDIATION_SERVICE_ACCOUNT else created_by_user

        def get_message_ts(self):
            """
            Returns message ts of initial message if user has not passed custom value
            """
            if self.rolling_restart.slack_alert_ts:
                self.logger.info("slack_alert_ts %s", self.rolling_restart.slack_alert_ts)
                return self.rolling_restart.slack_alert_ts
            return self.get_value(RR_MESSAGE_TS_KEY.format(guid=self.rolling_restart.guid))

        def is_cancelled(self):
            """
            Checks if current execution is cancelled
            """
            if self.rolling_restart.is_cancelled:
                self.add_event("Cancelling rolling restart, no new host will be processed", EventType.WARNING)

                # set each host state to cancelled
                for host in self.allocation_status.pending_hosts:
                    self.remediation_api_client.update_rolling_restart_host_status(
                        self.rolling_restart.guid, host, HOST_STATE_CANCELLED, message="Rolling restart is cancelled"
                    )
                # update rolling restart status to cancelled
                self.update_rolling_restart_status(STATE_CANCELLED)
                return True
            return False

        def is_expired(self):
            """
            Checks if current execution is expired
            """
            expire_cutoff_timestamp = TimeUtils.get_current_time_in_millis() - (EXPIRE_CUTOFF_HOURS * 60 * 60 * 1000)
            if self.rolling_restart.creation_ts_millis < expire_cutoff_timestamp:
                self.update_rolling_restart_status(STATE_TIMED_OUT)
                self.add_event(f"Expired rolling restart execution older than {EXPIRE_CUTOFF_HOURS} hours")
                return True
            return False

        def sync_rolling_restart_object(self):
            """
            Syncs rolling restart state from database
            """
            result = self.remediation_api_client.get_filtered_rolling_restart_actions(
                json.dumps({RR_GUID: self.rolling_restart.guid})
            )
            self.rolling_restart = self.parse_rr_dict(result[0])

        def trigger_restart_action(self, hosts):
            hosts_str = ", ".join(hosts)
            self.add_event(f"Triggered restart action for hosts {hosts_str}")
            self.send_slack_message(f"Triggering restarts on {hosts_str}")
            for hostname in hosts:
                metadata = MaievRemediationMetadata(
                    issue=ISSUE_TYPE_ROLLING_RESTART,
                    override_action=self.rolling_restart.action,
                    hosts=[hostname],
                    additional_info={},
                    incident_start_millis=TimeUtils.get_current_time_in_millis() - 5 * 60 * 1000,
                    send_thread_msg_to_channel=False,
                    script_args="",
                    create_case=False,
                    rolling_restart_guid=self.rolling_restart.guid,
                )
                try:
                    maiev_service = MaievRemediationService(metadata, self.runbook_context)
                    maiev_service.remediate()
                    self.remediation_api_client.update_rolling_restart_host_status(
                        self.rolling_restart.guid, hostname, HOST_STATE_REMEDIATION_CREATED
                    )
                except Exception as exc:
                    self.add_event(
                        f"Failed to create remediation action for {hostname}, Error: {exc}", EventType.WARNING
                    )
                    self.remediation_api_client.update_rolling_restart_host_status(
                        self.rolling_restart.guid, hostname, HOST_STATE_FAILED
                    )

        def update_rolling_restart_status(self, state, gus_case=None):
            """
            Updates rolling restart status and sync rolling_restart object
            """
            payload = {FIELD_STATE: state}
            if gus_case:
                payload["gus_case"] = gus_case
            response = self.remediation_api_client.update_rolling_restart_action(self.rolling_restart.guid, payload,)
            self.add_event(f"State transition : {self.rolling_restart.state} => {state}")
            self.send_slack_message(
                ROLLING_RESTART_STATE_TRANSITION_MSG.format(prev_state=self.rolling_restart.state, current_state=state)
            )
            self.rolling_restart = self.parse_rr_dict(response)

        def run_capacity_validation(self, raise_exception=True):
            """
            Gets capacity report for the pod
            """
            capacity_report = app_server_ping_alive_percent(
                self.rolling_restart.datacenter, self.rolling_restart.pod, self.argus_client
            )
            if isinstance(capacity_report, dict) and PING_ALIVE_PERCENT in capacity_report.keys():
                ping_alive_percent = capacity_report[PING_ALIVE_PERCENT]
                capacity = int(ping_alive_percent)
                if capacity == 0:
                    raise CapacityRetrievalFailed("Failed to get pod capacity report, error=Received 0, pls retry")
                elif capacity < self.capacity_cutoff_threshold:
                    error_msg = f"Current capacity: {capacity}%, Required capacity: {self.capacity_cutoff_threshold}%"
                    self.add_event(error_msg, EventType.ERROR)
                    if raise_exception:
                        raise LowPodCapacity(
                            f"Low Capacity Current capacity: {capacity}%, "
                            f"Required capacity: {self.capacity_cutoff_threshold}%"
                        )
                    return capacity
                self.add_event(f"Current capacity : {capacity}%, Required capacity : {self.capacity_cutoff_threshold}%")
                return capacity
            else:
                raise CapacityRetrievalFailed(f"Failed to get pod capacity report, error={capacity_report}")

        def create_change_case(self):
            """
            Creates change case
            """
            change_management_team = "a6nB0000000TU7SIAW"
            ctc_integration_category = "a8gEE0000137vk5YAA"
            fawkes_user = "005B0000005WssXIAS"
            # Create gus change management client

            subject = f"[AIOps rolling restart] [Observed symptom] Restarting apps in the cell [{self.pod}]"
            description = f"AIOps pipeline will be restarting apps in the cell [{self.pod}] \
            to bring them back to healthy state"

            # Create change case object
            change_case = GUSChangeCase(
                subject=subject,
                description=description,
                team_name=change_management_team,
                change_category=ctc_integration_category,
                pipeline=_FIREFLY_FCP_PIPELINE,
                business_reason="Incident Remediation",
                infrastructure_type="Supporting Infrastructure",
                source_control_tool=_SOURCE_CONTROL_TOOL,
                testing_method=_TESTING_METHOD_CHANGE_CASE,
                test_environment="Stage",
                backout_plan="N/A, no change is deployed",
                was_rollback_or_remediation_tested="No",
                why_is_the_rollback_plan_not_tested="rollback is not applicable as there is no change deployed.",
                what_is_the_stagger_plan="N/A, no change is deployed to production. Unhealthy Apps are just restarted to "
                "bring them back to healthy state",
                how_was_the_rollback_plan_tested="test-but-we-cannot-do-spaces-so-\
                            hyphens-are-the-way-to-go",
                if_manual_how_was_this_tested="By rebooting a single pod",
                if_not_tested_please_explain="tested",
                verification_plan="We monitor capacity of pod after restarting",
                risk_summary="No Risk, app are restarted to resolve incidents or prevent incidents during moratoriums",
                risk_level="Low",
            )
            # Create implementation Step Object
            ci_path = f"Salesforce.SFDC_Core.{self.datacenter.upper()}.{self.datacenter.upper()}-{self.superpod}.{self.pod.upper()}.app"
            step = GUSChangeImplementationStep(
                description=f"Core app restart for {self.pod} in Datacenter {self.datacenter} ",
                owner=fawkes_user,
                estimated_start_time=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                estimated_end_time=(datetime.datetime.utcnow() + datetime.timedelta(minutes=120)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                configuration_item_path=ci_path,
                infrastructure_type=_INFRASTRUCTURE_TYPE_CHANGE_CASE,
                implementation_steps=f"Core app restart for {self.pod} in Datacenter {self.datacenter} ",
            )
            self.logger.info("Creating change case")
            change_case = self.gus_cm_client.create_change_case(change_case, implementation_steps=[step])
            self.logger.info("Case creation response: %s", change_case)
            # Step 2: Submit for approval (Automatically gets approved on submission for Standard Pre-Approved Category)
            self.logger.info("Submitting Change case for approval")
            approval_response = self.gus_cm_client.submit_for_approval(
                change_case_id=change_case["id"], comment="Test CTC Api"
            )
            self.logger.info("Change case approval response: %s", approval_response)
            return change_case

        # pylint: disable=inconsistent-return-statements
        def create_gus_case(self):
            """
            Create gus case for rolling restart
            """
            subject = RR_CASE_SUBJECT.format(self.pod, self.rolling_restart.created_by)
            case = GUSCase(
                datacenter=self.datacenter,
                subject=subject if is_prod_env() else "[Test Pls Ignore] " + subject,
                description=subject,
                incident_start_time=TimeUtils.get_date_time_string(
                    time_stamp_millis=TimeUtils.get_current_time_in_millis(), dt_format="%Y-%m-%dT%H:%M:%S.000",
                ),
                team_id=CASP_TEAM_ID,
                instance=self.pod,
                status="New",
                priority=CASE_SEVERITY,
                case_origin="Detected by Monitoring",
                observed_symptom="Other",
            )
            case_payload = case.to_gus_payload()
            try:
                case = self.gus_client.create_sobject(case.get_sobject_name(), case_payload)
                if case:
                    self.logger.info("gus case created, case id=%s", case.get("id"))
                    return {"id": case.get("id")}

            except Exception as error:
                self.logger.error("Failed to create GUS case, error=%s", error)
                return None

        def gus_start_implementation(self, change_case):
            """Starts implementation step (Acquires lock on CI Updates actual start time automatically)"""
            self.logger.info("Starting implementation step")
            try:
                start_response = self.gus_cm_client.start_implementation_step(
                    implementation_steps=[change_case["implementationSteps"][0]]
                )
                self.logger.info("Starts implementation step response: %s", start_response)
            except Exception as error:
                self.logger.error(f"Failed to acquire CTC lock on pod: {self.pod}")
                raise Exception(error)

        def gus_stop_implementation(self):
            """Stop implementation step (Updates actual end time automatically)"""
            self.logger.info("Stopping implementation step")
            try:
                stop_response = self.gus_cm_client.stop_implementaion_steps(
                    {self.rolling_restart.gus_case["implementationSteps"][0]: CHANGE_IMPLEMENTATION_COMPLETED}
                )
                self.logger.info("Stop implementation step response: %s", stop_response)
            except Exception as error:
                self.logger.error("Exception while executing stop implementation step.Error= %s", error)

        def close_change_case(self):
            """Close change case"""
            self.logger.info("Closing change case")
            try:
                close_response = self.gus_cm_client.close_change_cases([self.rolling_restart.gus_case["id"]])
                self.logger.info("Close case response: %s", close_response)
            except Exception as error:
                self.logger.error("Exception while closing change case.Error= %s", error)

        def close_gus_case(self):
            """
            Close gus case if its created by Fawkes for rolling restart
            """
            if self.rolling_restart.gus_case:
                try:
                    resolution = "Fawkes attempted rolling restart on the pod"
                    response = RemediationGusClient.get_instance().update_sobject(
                        "Case",
                        self.rolling_restart.gus_case["id"],
                        {
                            GUS_FIELD_NAME_STATUS: "Closed",
                            GUS_FIELD_NAME_CATEGORY: "Application",
                            GUS_FIELD_NAME_ROOTCAUSE: "Core App",
                            GUS_FIELD_NAME_IMMEDIATE_RESOLUTION: resolution,
                        },
                    )
                    if response:
                        self.logger.info("Close Gus case response: %s", response)

                except Exception as error:
                    self.logger.error(
                        "Failed to close GUS case. Error=%s", error,
                    )

        def get_initial_capacity_state(self, guid, pod, datacenter):
            """
            Stores initial capacity and number of active hosts in kv store
            """
            # get values from kv store if already set
            pod_initial_capacity = int(self.get_value(RR_POD_INITIAL_CAPACITY.format(guid=guid)))
            active_hosts_count = int(self.get_value(RR_ACTIVE_HOST_COUNT.format(guid=guid)))

            # run capacity report and set values if not set
            if not pod_initial_capacity or not active_hosts_count:
                capacity_report = app_server_ping_alive_percent(datacenter, pod, self.argus_client)
                self.logger.info(f"Initial capacity report : {capacity_report}")
                if (
                    isinstance(capacity_report, dict)
                    and PING_ALIVE_PERCENT in capacity_report.keys()
                    and OPERATIONAL_STATUS in capacity_report.keys()
                ):
                    ping_alive_percent = capacity_report[PING_ALIVE_PERCENT]
                    pod_initial_capacity = int(ping_alive_percent)

                    active_hosts_count = None
                    for op_status in capacity_report[OPERATIONAL_STATUS]:
                        if op_status[0] == "ACTIVE":
                            active_hosts_count = op_status[1]
                            break
                    if not active_hosts_count:
                        raise CapacityRetrievalFailed("Failed to get active hosts info from initial capacity report")

                    self.set_value(
                        RR_POD_INITIAL_CAPACITY.format(guid=guid), pod_initial_capacity, ttl=KV_TTL_SECONDS,
                    )
                    self.set_value(RR_ACTIVE_HOST_COUNT.format(guid=guid), active_hosts_count, ttl=KV_TTL_SECONDS)
                else:
                    raise CapacityRetrievalFailed(f"Failed to get initial capacity report, error={capacity_report}")
            return active_hosts_count, pod_initial_capacity
