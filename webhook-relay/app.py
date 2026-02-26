#!/usr/bin/env python3
"""
SigNoz to Telegram Webhook Relay
Receives Alertmanager-format webhooks from SigNoz and forwards to Telegram
"""
import os
from flask import Flask, request, jsonify
import requests
from datetime import datetime

app = Flask(__name__)

# Load from environment
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

def format_alert_message(webhook_data):
    """Convert SigNoz webhook payload to Telegram message"""
    status = webhook_data.get('status', 'unknown')
    alerts = webhook_data.get('alerts', [])

    if not alerts:
        return "⚠️ Alert received but no alert details provided"

    messages = []
    for alert in alerts:
        alert_status = alert.get('status', status)
        labels = alert.get('labels', {})
        annotations = alert.get('annotations', {})

        # Status emoji
        emoji = "🔥" if alert_status == "firing" else "✅"

        # Build message
        msg_parts = [
            f"{emoji} *{labels.get('alertname', 'Unknown Alert')}*",
            f"*Status:* {alert_status.upper()}",
        ]

        # Add severity if present
        if 'severity' in labels:
            severity_emoji = {
                'critical': '🔴',
                'warning': '🟡',
                'info': '🔵'
            }.get(labels['severity'].lower(), '⚪')
            msg_parts.append(f"*Severity:* {severity_emoji} {labels['severity']}")

        # Add description
        if 'description' in annotations:
            msg_parts.append(f"\n{annotations['description']}")
        elif 'summary' in annotations:
            msg_parts.append(f"\n{annotations['summary']}")

        # Add labels
        relevant_labels = {k: v for k, v in labels.items()
                          if k not in ['alertname', 'severity']}
        if relevant_labels:
            label_str = ', '.join([f"{k}={v}" for k, v in relevant_labels.items()])
            msg_parts.append(f"\n*Labels:* `{label_str}`")

        # Add timestamp
        starts_at = alert.get('startsAt')
        if starts_at and starts_at != "0001-01-01T00:00:00Z":
            try:
                dt = datetime.fromisoformat(starts_at.replace('Z', '+00:00'))
                msg_parts.append(f"*Started:* {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            except:
                pass

        messages.append('\n'.join(msg_parts))

    return '\n\n---\n\n'.join(messages)

@app.route('/webhook', methods=['POST'])
def webhook():
    """Receive SigNoz webhook and forward to Telegram"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No JSON data received'}), 400

        # Format message for Telegram
        message = format_alert_message(data)

        # Send to Telegram
        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }

        response = requests.post(telegram_url, json=payload, timeout=10)

        if response.status_code == 200:
            return jsonify({'status': 'success', 'message': 'Alert sent to Telegram'}), 200
        else:
            return jsonify({
                'status': 'error',
                'message': f'Telegram API error: {response.text}'
            }), 500

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")
        exit(1)

    app.run(host='0.0.0.0', port=5000)
