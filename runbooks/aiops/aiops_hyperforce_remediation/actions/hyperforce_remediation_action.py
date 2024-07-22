"""
Action to execute actions on a target kpod in hyperforce
"""
import json
import os
import traceback
import datetime

from fawkes.action import FawkesAction
from fawkes.api.remediation import Remediation
from fawkes.connectors.gus.gus_change_management import GUSChangeManagement
from fawkes.connectors.gus.gus_objects import GUSCase
from fawkes.connectors.gus.gus_service import GUSRequestException
from fawkes.connectors.maiev.maiev_connector import MaievService
from fawkes.connectors.slack.message import Message, MessageTypes
from fawkes.constants import (
    SSL_CAFILE,
    SSL_CERTFILE,
    SSL_KEYFILE,
    AJNA_ENDPOINT,
)
from fawkes.utils.time_utils import TimeUtils
from statslib.senders.argus_sender import ArgusSender

from lib.constants import (
    CASE_SUBJECT_KPOD,
    CASE_SUBJECT_CELL,
    CASE_DESCRIPTION,
    CASE_SEVERITY,
    HYPERFORCE_ACTIONS_ETA_MILLIS,
    GUS_FEED_POST_TEXT,
    GUS_FEED_POST_ERROR_TEXT,
    STATSLIB_CONFIG_PATH,
    STATS_LIB_REMEDIATION_ACTION_COUNT,
    STATS_LIB_REMEDIATION_EXECUTION_TIME,
    MAIEV_ACTION_RESULT_LINK,
    CHANGE_IMPLEMENTATION_COMPLETED,
)
from lib.slack_templates import (
    REMEDIATION_REQUEST_RECEIVED,
    REMEDIATION_REQUEST_NOT_EXECUTED,
    REMEDIATION_ACTION_INITIATED,
    REMEDIATION_ACTION_FAILED,
    REMEDIATION_ACTION_COMPLETED,
    REMEDIATION_ACTION_RUN_TIME_ERROR,
    NOTIFICATION_REMEDIATION_MORE_INFO,
)
from lib.utils import close_gus_case, is_async_remediation_action
from shared.change_case.change_case_util import (
    create_change_case_from_template,
    gus_start_implementation,
    gus_stop_implementation,
    close_change_case,
)
from shared.common.utils import is_prod_env, is_dev_env
from shared.hyperforce.fkp_utils import get_active_k8s_pods
from shared.remediation.config import get_issue_config, get_action_config, Substrate
from shared.remediation.constants import (
    FAWKES_EXECUTION_LOGS_URL,
    FAWKES_LOGS_MESSAGE,
    REMEDIATION_ACTION_FINAL_STATES,
    HOST_ACTION_FAILED_ERROR_CODE,
    MAIEV_ACTION_SUCCESSFUL_STATUS_CODE,
    LOGS_LINK_TEXT,
)
from shared.remediation.enums import State
from shared.remediation.gus import RemediationGusClient
from shared.remediation.hyperforce_validation_handler import HyperforceValidationHandler
from shared.remediation.remediation_post_processor_handler import RemediationPostProcessorHandler
from shared.remediation.security import check_user_permissions
from shared.remediation.traffic_lights import RedLightException, YellowLightException
from shared.remediation.utils import (
    get_falcon_maiev_tenant_name,
    fetch_maeiv_action_result,
    get_slack_bot_token,
    get_container_name,
)

# pylint: disable=R0902,R0201
RUNTIME_ERROR = "RuntimeError"
MAIEV_RESULT_WINDOW = 1 * 60 * 60 * 1000  # 1 hour in millis


class HyperforceRemediationAction(FawkesAction):
    """
    Action class for hyperforce remediation actions
    """

    ACTION_EXPIRY_TIME_MILLIS = 5 * 60 * 1000
    STATE_IN_PROGRESS = "IN_PROGRESS"
    STATE_SUCCESSFUL = "SUCCESSFUL"
    STATE_FAILED = "FAILED"

    def __init__(self, config=None, action_service=None):
        super().__init__(config=config, action_service=action_service)
        self.maiev_service = MaievService.get_mock_instance() if is_dev_env() else MaievService()
        self.slack = Message()
        self.falcon_instance = ""
        self.functional_domain = ""
        self.kpod = ""
        self.remediation_action = None
        self.case_id = ""
        self.incident_start_millis = ""
        self.slack_bot_token = get_slack_bot_token()
        self.slack_channel_id = ""
        self.falcon_cell = ""
        self.slack_alert_ts = ""
        self.notify_slack = True
        self.create_change_case = False
        self.create_case = False
        self.issue_config = None
        self.action_config = None
        self.script_args = ""
        self.remediation_action = None
        self.is_maiev_k8s_script = False
        self.execute_action_from_any_kpod = True
        self.remediation_client = Remediation()
        self.execution_logs = FAWKES_EXECUTION_LOGS_URL.format(execution_id=os.getenv("ST2_ACTION_EXECUTION_ID", ""))
        self.gus_client = RemediationGusClient.get_instance()
        self.gus_cm_client = GUSChangeManagement(gus_client=self.gus_client)
        self.change_case = None
        self.argus_sender = ArgusSender(
            end_point=AJNA_ENDPOINT,
            config_file_path=STATSLIB_CONFIG_PATH,
            certs=(SSL_CERTFILE, SSL_KEYFILE),
            verify=SSL_CAFILE,
        )
        self.error_category = "not_available"
        self.active_kpods = []
        self.change_case_data = {}
        self.validation_params = {}
        self.fawkes_guid = ""
        self.send_thread_msg_to_channel = ""
        self.execution_logs_url = FAWKES_EXECUTION_LOGS_URL.format(
            execution_id=os.getenv("ST2_ACTION_EXECUTION_ID", "")
        )
        self.logs_link_text = LOGS_LINK_TEXT.format(logs_url=self.execution_logs_url)

    def do_run(self, **kwargs):
        """
        Method for running action
        """
        # checks permission of the initiator and throws exception if this user is not allowed to run action
        check_user_permissions(kwargs["initiator"])
        self.fawkes_guid = kwargs["fawkes_guid"]
        self.issue_config = get_issue_config(kwargs["issue"], substrate=Substrate.HYPERFORCE)
        self.action_config = self.get_action_config(kwargs["override_action"])
        self.falcon_instance = kwargs["falcon_instance"]
        self.functional_domain = kwargs["functional_domain"]
        self.kpod = kwargs["kpod"]
        self.execute_action_from_any_kpod = kwargs["execute_action_from_any_kpod"]
        self.is_maiev_k8s_script = self.action_config.is_maiev_k8s_script
        self.logger.info("Is maiev k8s script = %s", self.is_maiev_k8s_script)
        self.falcon_cell = kwargs["cell"]
        self.slack_alert_ts = kwargs["slack_alert_ts"]
        self.send_thread_msg_to_channel = kwargs["send_thread_msg_to_channel"]
        self.slack_channel_id = (
            self.issue_config.slack_channel if is_prod_env() else self.issue_config.slack_channel_dev
        )
        if kwargs.get("slack_channel_override", None):
            self.slack_channel_id = kwargs["slack_channel_override"]
        if kwargs["script_args"]:
            self.script_args = kwargs["script_args"]
        self.notify_slack = kwargs["notify_slack"] and self.slack_channel_id
        self.create_case = kwargs["create_case"]
        self.create_change_case = kwargs.get("create_change_case")
        self.incident_start_millis = kwargs["incident_start_millis"]
        self.validation_params = kwargs.get("validation_params")
        try:
            filter_params = {"guid": self.fawkes_guid}
            response = self.remediation_client.get_filtered_actions(json.dumps(filter_params))
            if not response:
                self.logger.info("[%s] remediation action not found for given guid, exiting", self.fawkes_guid)
                return
            self.remediation_action = response[0]
            self.send_remediation_requested_message()
            self.change_case_data = {
                "falcon_instance": self.falcon_instance,
                "functional_domain": self.functional_domain,
                "falcon_cell": self.falcon_cell,
                "estimated_start_time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "estimated_end_time": (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
            if self.create_change_case:
                self.change_case = create_change_case_from_template(
                    self.issue_config.change_case_template, self.change_case_data, self.gus_cm_client,
                )
            HyperforceValidationHandler(
                self.falcon_cell, self.falcon_instance, self.issue_config, self.action_config, self.validation_params
            ).check_traffic_lights()
            if self.create_change_case and self.change_case:
                gus_start_implementation(self.change_case, self.gus_cm_client)
            elif self.create_case:
                self.create_gus_case()

            if self.execute_action_from_any_kpod:
                if self.kpod:
                    self.active_kpods.append(self.kpod)
                container_name = get_container_name(self.action_config.role)
                active_k8s_pods_fetched = get_active_k8s_pods(
                    self.logger,
                    "aws",
                    self.falcon_instance,
                    self.functional_domain,
                    self.falcon_cell,
                    container=container_name,
                )
                active_k8s_pods_fetched = [pod for pod in active_k8s_pods_fetched if pod != self.kpod]
                self.active_kpods.extend(active_k8s_pods_fetched)
                if self.active_kpods and len(self.active_kpods) > 3:
                    self.logger.info(
                        "Active kpods count=%s for cell:%s, role:%s",
                        len(self.active_kpods),
                        self.falcon_cell,
                        self.action_config.role,
                    )
                    # take only 3 pods to try executing the action on
                    self.active_kpods = self.active_kpods[:3]
                self.logger.info(
                    "Active kpods considered for cell:%s, role:%s are %s.",
                    self.falcon_cell,
                    self.action_config.role,
                    self.active_kpods,
                )
            action_success = self.take_action()
            if action_success and is_async_remediation_action(self.remediation_action):
                self.logger.info("This is action is configured for async update. Exiting base action")
                return
            close_gus_case(self.remediation_action)
        except (RedLightException, YellowLightException) as error:
            self.logger.info(
                "Received RED/YELLOW light with message:%s - %s, not proceeding with action",
                error.__class__.__name__,
                error,
            )
            self.error_category = error.__class__.__name__
            # setting raise_exception to false to publish metric even the slack notification fails
            more_details = f"{error.__class__.__name__} - {error}"
            message = REMEDIATION_REQUEST_NOT_EXECUTED.format(more_details=more_details)
            self.send_slack_message(message)
            if self.create_change_case and self.change_case:
                gus_stop_implementation(self.gus_cm_client, self.change_case, CHANGE_IMPLEMENTATION_COMPLETED)
                close_change_case(self.gus_cm_client, self.change_case)
            close_gus_case(self.remediation_action)
            return
        except Exception as error:
            self.send_slack_message(REMEDIATION_ACTION_RUN_TIME_ERROR.format(action=self.action_config.guid))
            if self.create_change_case and self.change_case:
                gus_stop_implementation(self.gus_cm_client, self.change_case, CHANGE_IMPLEMENTATION_COMPLETED)
                close_change_case(self.gus_cm_client, self.change_case)
            elif self.case_id:
                self.error_chatter_post(error)
            close_gus_case(self.remediation_action)
            self.logger.error("Action failed with error:%s, traceback:%s", error, traceback.format_exc())
            raise
        finally:
            if self.remediation_action["state"] in REMEDIATION_ACTION_FINAL_STATES:
                try:
                    RemediationPostProcessorHandler(self.remediation_action).run_post_processors()
                except Exception as error:
                    self.logger.error(
                        "Post processing failed with error:%s, traceback:%s", error, traceback.format_exc()
                    )

    def send_remediation_requested_message(self):
        """
        Send remediation requested message to slack
        """
        more_details = FAWKES_LOGS_MESSAGE.format(logs_url=self.execution_logs)
        message = REMEDIATION_REQUEST_RECEIVED.format(
            guid=self.remediation_action["guid"],
            issue=self.issue_config.guid,
            kpod=self.remediation_action["kpod"],
            action=self.action_config.guid,
            more_details=more_details,
        )
        self.send_slack_message(message)

    def _set_action_status(self, action, state, status_code=None, action_result=None, additional_info=None):

        payload = {"state": state}
        if state in REMEDIATION_ACTION_FINAL_STATES:
            if status_code:
                payload["status_code"] = status_code
            else:
                raise ValueError("status code missing for final state")

        if additional_info:
            payload["additional_info"] = additional_info
        if action_result:
            payload["action_result"] = action_result
        self.logger.info("updating action status with payload:%s", payload)
        return self.remediation_client.update_action(action["guid"], payload)

    def get_action_config(self, override_action):
        """
        Gets action config for the issue
        """
        if override_action:
            return get_action_config(override_action, Substrate.HYPERFORCE)
        return get_action_config(self.issue_config.remediation_action, Substrate.HYPERFORCE)

    def _create_action(self):
        """
        creates remediation actions in fawkes DB
        """
        current_time_millis = TimeUtils.get_current_time_in_millis()
        payload = {
            "action": self.action_config.guid,
            "issue": self.issue_config.guid,
            "incident_start_millis": self.incident_start_millis,
            "kpod": self.kpod,
            "cell": self.falcon_cell,
            "falcon_instance": self.falcon_instance,
            "team_id": self.issue_config.gus_team_id,
            "expiry_ts_millis": current_time_millis + self.ACTION_EXPIRY_TIME_MILLIS,
            "substrate": "hyperforce",
        }
        try:
            remediation_action = self.remediation_client.create_remediation_action(payload)
            self.logger.info("Remediation action created. Action details:%s", remediation_action)
            return remediation_action
        except Exception as error:
            self.logger.error("Error while creating remediation action.Error:%s", error)
            raise

    def create_gus_case(self):
        """
        creates GUS case for remediation action
        """
        datacenter = self.falcon_instance
        case_subject = (
            CASE_SUBJECT_KPOD.format(issue=self.action_config.name, kpod=self.kpod)
            if self.kpod
            else CASE_SUBJECT_CELL.format(issue=self.action_config.name, cell=self.falcon_cell)
        )
        subject = case_subject if is_prod_env() else "[Test Please ignore] " + case_subject
        case_description = CASE_DESCRIPTION.format(action=self.action_config.name)
        start_time_ms = TimeUtils.get_current_time_in_millis()
        case = GUSCase(
            datacenter=datacenter,
            subject=subject,
            description=case_description,
            incident_start_time=TimeUtils.get_date_time_string(
                time_stamp_millis=int(start_time_ms), dt_format="%Y-%m-%dT%H:%M:%S.000",
            ),
            team_id="a00B0000000wegMIAQ",
            instance=self.falcon_cell,
            status="New",
            priority=CASE_SEVERITY,
            case_origin="Detected by Monitoring",
            observed_symptom="Other",
        )
        case_payload = case.to_gus_payload()
        try:
            case = RemediationGusClient.get_instance().create_sobject(case.get_sobject_name(), case_payload)
            if case:
                self.case_id = case["id"]
                self.logger.info("Case created succesfully, id=%s", self.case_id)
        except GUSRequestException as error:
            self.logger.error(
                "Failed to create GUS case for remediation action, Error=%s", error,
            )

    def send_slack_message(self, message, message_type=MessageTypes.MARKDOWN):
        """
        Sends slack message for the action
        """
        if self.notify_slack:
            slack_ts = self.slack.send_thread_message(
                self.slack_bot_token, self.slack_channel_id, message, self.slack_alert_ts, message_type=message_type
            )
            if not self.slack_alert_ts:
                self.slack_alert_ts = slack_ts

    def take_action(self):
        """
        Takes aciton on the kpod
        """
        slack_message = "N/A"
        action_executed = False
        status_updated = False
        maiev_guid = None
        if not self.execute_action_from_any_kpod and self.kpod:
            kpods = [self.kpod]
        else:
            kpods = self.active_kpods
        action_name = self.remediation_action["action"]
        for kpod in kpods:
            try:
                self.logger.info(f"Trying to trigger remediation action from kpod : {kpod}")
                maiev_tenant = get_falcon_maiev_tenant_name(
                    self.falcon_instance, self.functional_domain, self.falcon_cell, self.action_config.role
                )
                self.logger.info(
                    "maiev tenant for fi-fd-cell-role: <%s>-<%s>-<%s>-<%s> is %s",
                    self.falcon_instance,
                    self.functional_domain,
                    self.falcon_cell,
                    self.action_config.role,
                    maiev_tenant,
                )
                script_name = self.get_script_name()
                maiev_response = self.maiev_service.submit_hyperforce_action(
                    maiev_tenant,
                    kpod,
                    script_name,
                    self.remediation_action["guid"],
                    self.script_args,
                    self.get_script_path(),
                    self.is_maiev_k8s_script,
                )
                response_json = maiev_response.json()
                maiev_guid = response_json.get("action_guid")
                self.logger.info(
                    "Maiev action submitted for kpod :%s, guid :%s, script_name: %s, script_args=%s",
                    kpod,
                    maiev_guid,
                    script_name,
                    self.script_args,
                )
                if not status_updated:
                    self.send_slack_message(
                        REMEDIATION_ACTION_INITIATED.format(action=action_name, case_id=self.case_id)
                    )
                    self.remediation_action = self.remediation_client.update_action(
                        self.fawkes_guid,
                        {
                            "state": State.IN_PROGRESS.value,
                            "gus_case_id": self.case_id,
                            "additional_info": {
                                "change_case": self.change_case,
                                "slack": {
                                    "notify": self.notify_slack,
                                    "alert_message_ts": self.slack_alert_ts,
                                    "alert_channel_id": self.slack_channel_id,
                                    "send_thread_msg_to_channel": self.send_thread_msg_to_channel,
                                },
                            },
                        },
                    )
                    status_updated = True
                self.remediation_action = self._set_action_status(
                    action=self.remediation_action,
                    state=self.STATE_IN_PROGRESS,
                    additional_info={"maiev_guid": maiev_guid,},
                )
                if is_async_remediation_action(self.remediation_action):
                    self.logger.info("This action is configured for async update. Skipping result polling loop")
                    return True
                expiry_time = TimeUtils.get_current_time_in_millis() + HYPERFORCE_ACTIONS_ETA_MILLIS
                result = fetch_maeiv_action_result(self.maiev_service, maiev_guid, expiry_time)
                self.logger.info("maiev action result=%s", result)
                if result[0]:
                    action_executed = True
                    self.remediation_action = self._set_action_status(
                        action=self.remediation_action,
                        state=self.STATE_SUCCESSFUL,
                        status_code=MAIEV_ACTION_SUCCESSFUL_STATUS_CODE,
                        action_result="action successful",
                    )
                    slack_message = REMEDIATION_ACTION_COMPLETED.format(action=action_name)
                    break
                else:
                    self.logger.info("Action was not successful from kpod: %s, maiev guid: %s", kpod, maiev_guid)
            except Exception as error:
                self.logger.error(
                    "Exception while taking action %s, from kpod: %s, error: %s, traceback:%s",
                    self.remediation_action,
                    kpod,
                    error,
                    traceback.format_exc(),
                )
        if not action_executed:
            if not kpods:
                slack_message = f"No active kpods found in {self.falcon_cell} to execute the action"
            else:
                self.logger.info("Action was not successful from any of the Maiev side cars")
                slack_message = REMEDIATION_ACTION_FAILED.format(
                    action=action_name, guid=maiev_guid, link=self.logs_link_text
                )
            self.remediation_action = self._set_action_status(
                action=self.remediation_action,
                state=self.STATE_FAILED,
                status_code=HOST_ACTION_FAILED_ERROR_CODE,
                action_result="action failed",
            )
        self.send_slack_message(slack_message)
        maiev_result_endtime = self.remediation_action["creation_ts_millis"] + MAIEV_RESULT_WINDOW
        maiev_result_link = self.get_maiev_action_result_link(
            maiev_guid=maiev_guid,
            start_time_millis=self.remediation_action["creation_ts_millis"],
            end_time_millis=maiev_result_endtime,
        )
        self.send_slack_message(NOTIFICATION_REMEDIATION_MORE_INFO.format(maiev_result_link=maiev_result_link))
        if self.create_change_case and self.change_case:
            gus_stop_implementation(self.gus_cm_client, self.change_case, CHANGE_IMPLEMENTATION_COMPLETED)
            close_change_case(self.gus_cm_client, self.change_case)
        self.publish_metric()
        if self.case_id:
            self.make_chatter_post()
        return action_executed

    def publish_metric(self):
        """
        publish metric to argus for action taken
        """
        try:
            self.argus_sender.send(
                STATS_LIB_REMEDIATION_ACTION_COUNT,
                value=1,
                tags={
                    "issue": self.remediation_action["issue"],
                    "action": self.remediation_action["action"],
                    "cell": self.remediation_action["cell"],
                    "kpod": self.remediation_action["kpod"],
                    "fi": self.remediation_action["falcon_instance"],
                    "status": self.remediation_action["state"],
                },
            )

            self.argus_sender.send(
                STATS_LIB_REMEDIATION_EXECUTION_TIME,
                value=3,
                tags={
                    "issue": self.remediation_action["issue"],
                    "action": self.remediation_action["action"],
                    "cell": self.remediation_action["cell"],
                    "kpod": self.remediation_action["kpod"],
                    "status_code": self.remediation_action["status_code"],
                    "error": self.error_category,
                },
            )

            self.argus_sender.shutdown()
        except Exception as error:
            self.logger.error("Exception while sending argus metric, error:%s", error)

    def get_script_name(self):
        """
        returns script name and params
        """
        maiev_scripts = self.action_config.maiev_scripts
        return maiev_scripts[0]

    def get_script_path(self):
        """
        returns script path
        """
        return self.action_config.maiev_script_path

    def make_chatter_post(self):
        """
        Makes chatter post on the case
        """
        try:
            self.gus_client.create_feed_item(self.case_id, GUS_FEED_POST_TEXT.format(self.action_config.name))
        except GUSRequestException as error:
            self.logger.error(
                "[%s] Failed to post chatter message in GUS case for remediation action. Error=%s",
                self.remediation_action["guid"],
                error,
            )

    def error_chatter_post(self, msg):
        """
        Makes chatter error post on the case
        """
        try:
            self.gus_client.create_feed_item(
                self.case_id, GUS_FEED_POST_ERROR_TEXT.format(self.action_config.name, msg)
            )
        except GUSRequestException as error:
            self.logger.error(
                "[%s] Failed to post chatter message in GUS case for remediation action. Error=%s",
                self.remediation_action["guid"],
                error,
            )

    def get_maiev_action_result_link(self, maiev_guid, start_time_millis, end_time_millis):
        """
        Generates maiev action result link
        """
        return MAIEV_ACTION_RESULT_LINK.format(
            guid=maiev_guid, start_time_millis=start_time_millis, end_time_millis=end_time_millis
        )
