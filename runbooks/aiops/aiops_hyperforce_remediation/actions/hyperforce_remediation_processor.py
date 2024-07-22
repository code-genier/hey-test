import json
import os
from fawkes.action import FawkesAction
from fawkes.api.remediation import Remediation
from fawkes.connectors.maiev.maiev_connector import MaievService
from fawkes.connectors.slack.message import Message, MessageTypes
from fawkes.constants import (
    FAWKES_ENV,
    PROD_ENV,
    STAGE_ENV,
    FALCON_ENV,
    AJNA_ENDPOINT,
    SSL_CERTFILE,
    SSL_KEYFILE,
    SSL_CAFILE,
)
from fawkes.utils.time_utils import TimeUtils
from shared.remediation.gus import RemediationGusClient
from fawkes.connectors.gus.gus_change_management import GUSChangeManagement
from statslib.senders.argus_sender import ArgusSender

from lib.constants import CHANGE_IMPLEMENTATION_COMPLETED, STATSLIB_CONFIG_PATH, ASYNC_ISSUE_TYPES
from runbooks.aiops.aiops_hyperforce_remediation.actions.lib.slack_templates import (
    REMEDIATION_ACTION_COMPLETED,
    REMEDIATION_ACTION_FAILED,
    NOTIFICATION_REMEDIATION_MORE_INFO,
    REMEDIATION_ACTION_EXPIRED,
)
from runbooks.aiops.aiops_hyperforce_remediation.actions.lib.utils import (
    close_gus_case,
    get_maiev_action_result_link,
    publish_metric,
)
from shared.change_case.change_case_util import gus_stop_implementation, close_change_case
from shared.remediation.constants import (
    MAIEV_ACTION_EXPIRED_ERROR_CODE,
    HOST_ACTION_FAILED_ERROR_CODE,
    MAIEV_ACTION_REJECTED_ERROR_CODE,
    FAWKES_EXECUTION_LOGS_URL,
    LOGS_LINK_TEXT,
    REMEDIATION_ACTION_FINAL_STATES,
)
from shared.remediation.enums import State, ActionResponse
from shared.remediation.remediation_post_processor_handler import RemediationPostProcessorHandler
from shared.remediation.utils import get_slack_bot_token

LOOK_BACK_WINDOW = 2 * 60 * 60 * 1000  # 2 hours in millis
MAIEV_RESULT_WINDOW = 1 * 60 * 60 * 1000  # 1 hour in millis


class HyperforceRemediationProcessor(FawkesAction):
    """
    Hyperforce Remediation async processor class
    """

    def __init__(self, config=None, action_service=None):
        super(HyperforceRemediationProcessor, self).__init__(config=config, action_service=action_service)
        self.api_client = Remediation()
        self.slack_client = Message(runbook_context=self.runbook_context)
        if FAWKES_ENV in [PROD_ENV, STAGE_ENV, FALCON_ENV]:
            self.maiev_client = MaievService()
        else:
            self.logger.info("Initiating mock instance of MaievService on env %s", FALCON_ENV)
            self.maiev_client = MaievService.get_mock_instance()
        self.execution_logs_url = FAWKES_EXECUTION_LOGS_URL.format(
            execution_id=os.getenv("ST2_ACTION_EXECUTION_ID", "")
        )
        self.argus_sender = ArgusSender(
            end_point=AJNA_ENDPOINT,
            config_file_path=STATSLIB_CONFIG_PATH,
            certs=(SSL_CERTFILE, SSL_KEYFILE),
            verify=SSL_CAFILE,
        )
        self.gus_client = RemediationGusClient.get_instance()
        self.gus_cm_client = GUSChangeManagement(gus_client=self.gus_client)

    def do_run(self, **kwargs):
        """
        Run async updater
        """
        current_timestamp = TimeUtils.get_current_time_in_millis()
        creation_time_millis = current_timestamp - LOOK_BACK_WINDOW
        remediation_actions = self.api_client.get_filtered_actions(
            json.dumps({"state": State.IN_PROGRESS.value, "creation_ts_millis": {"$gte": creation_time_millis},})
        )

        self.logger.info(
            f"Found {len(remediation_actions)} open remediation actions created after {creation_time_millis}"
        )

        for remediation in remediation_actions:
            try:
                # TODO: add conditions here to avoid running processor for specific issue/action type like rolling
                #  restarts
                if remediation["issue"] not in ASYNC_ISSUE_TYPES or remediation["substrate"] != "hyperforce":
                    continue
                remediation_guid = remediation["guid"]
                self.logger.info("[%s] tracking remediation action", remediation_guid)
                maiev_action_guid = remediation["additional_info"]["maiev_guid"]
                response = self.poll_status(maiev_action_guid, remediation_guid)
                logs_link_text = LOGS_LINK_TEXT.format(logs_url=self.execution_logs_url)
                if not response:
                    self.logger.info("[%s] remediation action is not completed...", remediation_guid)
                    if current_timestamp > remediation["expiry_ts_millis"]:
                        self.logger.info("[%s] expiring remediation action", remediation_guid)
                        self.api_client.update_action(
                            remediation["guid"],
                            {
                                "state": State.EXPIRED.value,
                                "status_code": MAIEV_ACTION_EXPIRED_ERROR_CODE,
                                "action_result": "Unable to fetch maiev result within expiry time",
                            },
                        )
                        # close change case
                        if remediation["additional_info"].get("change_case"):
                            gus_stop_implementation(
                                self.gus_cm_client,
                                remediation["additional_info"].get("change_case"),
                                CHANGE_IMPLEMENTATION_COMPLETED,
                            )
                            close_change_case(self.gus_cm_client, remediation["additional_info"].get("change_case"))
                        # close gus case
                        close_gus_case(remediation)
                        self.send_slack_message(
                            remediation,
                            REMEDIATION_ACTION_EXPIRED.format(
                                action=remediation["action"], guid=maiev_action_guid, link=logs_link_text
                            ),
                        )
                    continue
                self.logger.info(
                    "[%s] action response is state=%s, status_code=%s",
                    remediation_guid,
                    response.state,
                    response.status_code,
                )
                remediation_action = self.api_client.update_action(
                    remediation["guid"],
                    {
                        "state": response.state.value,
                        "status_code": response.status_code,
                        "action_result": response.result,
                    },
                )

                # close change case
                if remediation_action["additional_info"].get("change_case"):
                    gus_stop_implementation(
                        self.gus_cm_client,
                        remediation["additional_info"].get("change_case"),
                        CHANGE_IMPLEMENTATION_COMPLETED,
                    )
                    close_change_case(self.gus_cm_client, remediation["additional_info"].get("change_case"))

                # publish argus metric
                publish_metric(self.argus_sender, remediation_action)

                if response.state == State.SUCCESSFUL:
                    self.send_slack_message(
                        remediation_action, REMEDIATION_ACTION_COMPLETED.format(action=remediation_action["action"])
                    )

                else:
                    self.send_slack_message(
                        remediation_action,
                        REMEDIATION_ACTION_FAILED.format(
                            action=remediation_action["action"], guid=maiev_action_guid, link=logs_link_text
                        ),
                    )
                close_gus_case(remediation_action)
                maiev_result_endtime = remediation_action["creation_ts_millis"] + MAIEV_RESULT_WINDOW
                maiev_result_link = get_maiev_action_result_link(
                    maiev_guid=maiev_action_guid,
                    start_time_millis=remediation_action["creation_ts_millis"],
                    end_time_millis=maiev_result_endtime,
                )
                self.send_slack_message(
                    remediation_action, NOTIFICATION_REMEDIATION_MORE_INFO.format(maiev_result_link=maiev_result_link)
                )
                if remediation_action["state"] in REMEDIATION_ACTION_FINAL_STATES:
                    RemediationPostProcessorHandler(remediation_action).run_post_processors()

            except Exception as exc:
                self.logger.exception(
                    "error occurred in remediation processor, remediation guid: %s, maiev action guid: %s, error:%s",
                    remediation["guid"],
                    remediation["additional_info"]["maiev_guid"],
                    exc,
                )
        self.argus_sender.shutdown()

    def poll_status(self, maiev_action_guid, remediation_guid):
        """
        Polls status of maiev action
        """
        action_result = self.maiev_client.query_action_result(maiev_action_guid)
        metadata = action_result.get("metadata")
        # ignore the response if metadata is empty as the action might not be completed yet
        if metadata:
            success = metadata.get("success")
            payload = metadata.get("payload")
            if success and json.loads(success):
                exit_code = metadata.get("exit_code")
                if int(exit_code) == 0:
                    self.logger.info("Maiev action successful")
                    return ActionResponse(State.SUCCESSFUL, 200, payload)
                elif int(exit_code) == -1975219:
                    self.logger.info("Kubernetes did not properly disconnect but action did not necessarily fail")
                    return ActionResponse(State.SUCCESSFUL, 200, payload)
                self.logger.info("Maiev action returned non-zero exit code")
                return ActionResponse(State.FAILED, HOST_ACTION_FAILED_ERROR_CODE, payload)
            else:
                self.logger.info("Maiev could not run the action")
                return ActionResponse(State.FAILED, MAIEV_ACTION_REJECTED_ERROR_CODE, payload)
        self.logger.info("[%s] maiev response: %s", remediation_guid, action_result)
        return None

    def send_slack_message(self, remediation_action, message, message_type=MessageTypes.MARKDOWN):
        """
        Sends slack message for the action
        """
        try:
            slack_bot_token = get_slack_bot_token()
            notify_slack = remediation_action["additional_info"]["slack"]["notify"]
            alert_channel_id = remediation_action["additional_info"]["slack"]["alert_channel_id"]
            alert_message_ts = remediation_action["additional_info"]["slack"]["alert_message_ts"]
            if notify_slack:
                self.slack_client.send_thread_message(
                    slack_bot_token, alert_channel_id, message, alert_message_ts, message_type=message_type
                )
        except Exception as exc:
            self.logger.error(
                "[%s] Failed to send slack notification, error=%s, payload=%s", remediation_action["guid"], exc, message
            )
