import json
import logging
import requests
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import html  # Added for HTML entity decoding

log_path = Path("/var/ossec/logs/custom-teams.py.log")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(log_path, mode="a", encoding="utf-8"),
    ],
)


@dataclass(slots=True)
class Alert:
    rule_id: int
    rule_level: int
    rule_description: str
    agent_id: int
    agent_name: str
    full_log: str


def get_severity_color(rule_level: int) -> str:
    if rule_level >= 10:
        return "attention"  # red
    if rule_level >= 7:
        return "warning"  # yellow
    if rule_level >= 4:
        return "good"  # green
    return "accent"  # dark gray


def generate_adaptive_card(alert: Alert) -> dict[str, Any]:
    severity_color = get_severity_color(alert.rule_level)
    logging.info("Generating MS Teams Adaptive Card")

    adaptive_card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.3",
        "msteams": {"width": "Full"},
        "body": [
            {
                "type": "Container",
                "style": severity_color,
                "bleed": True,
                "items": [
                    {"type": "TextBlock", "text": f"{alert.rule_description}", "weight": "Bolder"}
                ],
            },
            {
                "type": "RichTextBlock",
                "inlines": [
                    {"type": "TextRun", "text": "Agent: ", "weight": "Bolder"},
                    {"type": "TextRun", "text": f"{alert.agent_name} "},
                    {"type": "TextRun", "text": f"(ID {alert.agent_id})", "italic": True},
                ],
            },
            {
                "type": "RichTextBlock",
                "inlines": [
                    {"type": "TextRun", "text": "Rule: ", "weight": "Bolder"},
                    {"type": "TextRun", "text": f"{alert.rule_id} "},
                    {"type": "TextRun", "text": f"(Level {alert.rule_level})", "italic": True},
                ],
            },
            {
                "type": "Container",
                "id": "showToggle",
                "spacing": "Medium",
                "separator": True,
                "items": [
                    {
                        "type": "ActionSet",
                        "actions": [
                            {
                                "type": "Action.ToggleVisibility",
                                "title": "Show Full Log ▸",
                                "targetElements": [
                                    {"elementId": "fullLogBlock", "isVisible": True},
                                    {"elementId": "showToggle", "isVisible": False},
                                    {"elementId": "hideToggle", "isVisible": True},
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "type": "Container",
                "id": "hideToggle",
                "isVisible": False,
                "items": [
                    {
                        "type": "ActionSet",
                        "actions": [
                            {
                                "type": "Action.ToggleVisibility",
                                "title": "Hide Full Log ▾",
                                "targetElements": [
                                    {"elementId": "fullLogBlock", "isVisible": False},
                                    {"elementId": "showToggle", "isVisible": True},
                                    {"elementId": "hideToggle", "isVisible": False},
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "type": "Container",
                "id": "fullLogBlock",
                "isVisible": False,
                "style": "emphasis",
                "bleed": False,
                "spacing": "Small",
                "items": [
                    {"type": "TextBlock", "text": alert.full_log, "wrap": True, "maxLines": 0, "fontType": "Monospace"}
                ],
            },
        ],
        "fallbackText": "Wazuh Alert",
    }

    return adaptive_card


def get_alert_details(alert_file_path: str) -> Alert:
    with open(alert_file_path) as alert_file:
        alert_body = json.load(alert_file)
    logging.debug(alert_body)

    rule_id = int(alert_body["rule"]["id"])
    rule_level = int(alert_body["rule"]["level"])
    rule_description = str(alert_body["rule"]["description"]) or "Wazuh Alert"
    agent_id = int(alert_body["agent"]["id"])
    agent_name = str(alert_body["agent"]["name"])
    full_log = str(alert_body["full_log"])

    return Alert(
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description=rule_description,
        agent_id=agent_id,
        agent_name=agent_name,
        full_log=full_log,
    )


def send_message(adaptive_card: dict[str, Any], webhook: str) -> None:
    # Decode any HTML entities in the webhook URL
    webhook = html.unescape(webhook)

    headers = {"Content-Type": "application/json"}
    payload = json.dumps(adaptive_card)

    logging.info(f"Sending message to Power Automate: {payload}")
    logging.info(f"Using webhook URL: {webhook}")

    response = requests.post(url=webhook, headers=headers, data=payload, timeout=60)

    if not response.ok:
        logging.error("Failed to send message!")
        logging.error(f"Response code: {response.status_code}, response body: {response.text}")
    else:
        logging.info("Successfully sent message to Power Automate")


def handle_alert(args: list[str]) -> None:
    alert_file_path = args[1]
    webhook = args[3]
    alert = get_alert_details(alert_file_path)
    adaptive_card = generate_adaptive_card(alert)
    send_message(adaptive_card, webhook)


if __name__ == "__main__":
    try:
        logging.debug(sys.argv)
        handle_alert(sys.argv)
    except Exception as e:
        logging.error(str(e))
        raise
